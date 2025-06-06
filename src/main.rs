mod record;
mod handshake;
mod crypto;
mod server_hello;
mod encrypted_extensions;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use ring::{
    agreement,
    rand::{SystemRandom, SecureRandom},
    digest,
    error::Unspecified,
};

#[tokio::main]
async fn main() -> Result<()> {
    // TCPリスナーをポート4433で開始
    let listener = match TcpListener::bind("127.0.0.1:4433").await {
        Ok(l) => l,
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to start server: {}", e));
        }
    };

    // クライアントの接続を待機
    let (mut socket, _) = match listener.accept().await {
        Ok(conn) => conn,
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to accept connection: {}", e));
        }
    };

    // クライアントからのデータを読み込む
    let mut buffer = [0u8; 4096];
    let n = socket.read(&mut buffer).await?;

    // TLSレコードレイヤーの解析
    let record = record::TLSPlaintext::from_bytes(&buffer[..n])
        .ok_or_else(|| anyhow::anyhow!("Invalid record"))?;

    if record.content_type != record::ContentType::Handshake {
        return Err(anyhow::anyhow!("Expected Handshake record"));
    }

    // ClientHelloの解析
    let client_hello = handshake::ClientHello::from_bytes(&record.fragment)
        .ok_or_else(|| anyhow::anyhow!("Invalid ClientHello"))?;

    // 鍵交換の準備
    let rng = SystemRandom::new();
    let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        .map_err(|e| anyhow::anyhow!("Failed to generate private key: {}", e))?;
    let public_key = private_key.compute_public_key()
        .map_err(|e| anyhow::anyhow!("Failed to compute public key: {}", e))?;

    // サーバーの公開鍵をそのまま使用
    let _server_kx = public_key.as_ref().to_vec();

    // サーバーの乱数を生成（クライアントの乱数をコピーするのではなく）
    let mut server_random = [0u8; 32];
    rng.fill(&mut server_random)
        .map_err(|e: Unspecified| anyhow::anyhow!("Failed to generate server random: {:?}", e))?;

    // クライアントの暗号スイート提案から適切なものを選択
    let selected_cipher_suite = *client_hello.cipher_suites.iter()
        .find(|&&suite| {
            // TLS 1.3の暗号スイートのみをサポート
            match suite {
                0x1301 => true, // TLS_AES_128_GCM_SHA256
                0x1302 => true, // TLS_AES_256_GCM_SHA384
                0x1303 => true, // TLS_CHACHA20_POLY1305_SHA256
                _ => false,
            }
        })
        .ok_or_else(|| anyhow::anyhow!("No supported TLS 1.3 cipher suite"))?;

    // 暗号スイートに応じてサポートする署名アルゴリズムを決定
    let supported_signature_algorithms = match selected_cipher_suite {
        0x1302 => vec![0x0503], // TLS_AES_256_GCM_SHA384 → ecdsa_secp384r1_sha384
        _ => vec![0x0403, 0x0804], // TLS_AES_128_GCM_SHA256/TLS_CHACHA20_POLY1305_SHA256 → ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256
    };

    // 署名アルゴリズムの選択
    let signature_algorithms_ext = client_hello.extensions.iter()
        .find(|ext| ext.extension_type == 0x000d) // signature_algorithms
        .ok_or_else(|| anyhow::anyhow!("No signature_algorithms extension"))?;

    // signature_algorithms拡張のデータ構造を解析
    let ext_data = &signature_algorithms_ext.extension_data;
    if ext_data.len() < 2 {
        return Err(anyhow::anyhow!("Invalid signature_algorithms extension data: too short"));
    }

    // 署名アルゴリズムリストの長さを取得
    let total_length = ((ext_data[0] as u16) << 8 | ext_data[1] as u16) as usize;
    if total_length + 2 != ext_data.len() {
        return Err(anyhow::anyhow!("Invalid signature_algorithms extension data length"));
    }

    // クライアントの署名アルゴリズムリストから、サーバーがサポートしているものを選択
    let mut selected_signature_alg = None;
    for i in (2..ext_data.len()).step_by(2) {
        if i + 1 >= ext_data.len() {
            break;
        }
        let alg = ((ext_data[i] as u16) << 8) | (ext_data[i + 1] as u16);
        if supported_signature_algorithms.contains(&alg) {
            selected_signature_alg = Some(alg);
            break;
        }
    }

    let selected_signature_alg = selected_signature_alg
        .ok_or_else(|| anyhow::anyhow!("No supported signature algorithm found"))?;

    // ServerHelloメッセージの構築
    let server_hello = server_hello::ServerHello::new(
        0x0303, // TLS 1.2
        server_random,
        client_hello.session_id,
        selected_cipher_suite,
        0x00, // NULL圧縮
        vec![
            server_hello::Extension {
                extension_type: 0x002b, // supported_versions
                extension_data: vec![0x03, 0x04], // TLS 1.3
            },
            server_hello::Extension {
                extension_type: 0x0033, // key_share
                extension_data: {
                    let mut key_share = Vec::new();
                    key_share.push(0x00); // NamedGroup::x25519
                    key_share.push(0x1d);
                    key_share.push(0x00); // 32バイト固定長
                    key_share.push(0x20);
                    key_share.extend_from_slice(public_key.as_ref());
                    key_share
                },
            },
        ],
    );
    let server_hello_bytes = server_hello.to_bytes();

    // ハンドシェイクメッセージのみを連結（レコードヘッダーなし）
    let mut handshake_messages_till_sh = Vec::new();
    let client_hello_bytes = &record.fragment;
    handshake_messages_till_sh.extend_from_slice(client_hello_bytes);
    handshake_messages_till_sh.extend_from_slice(&server_hello_bytes);

    // トランスクリプトハッシュの計算（ClientHello + ServerHello）
    let hkdf_alg = crypto::hkdf_alg_from_suite(selected_cipher_suite);
    let digest_alg = crypto::digest_alg_from_hkdf(hkdf_alg);
    let mut transcript_hash = digest::digest(digest_alg, &handshake_messages_till_sh);

    // ServerHelloの送信
    let server_hello_record = record::TLSPlaintext::new(
        record::ContentType::Handshake,
        server_hello_bytes.clone(),
    );
    socket.write_all(&server_hello_record.to_bytes()).await?;

    // 共有秘密の導出
    let key_share_ext = client_hello.extensions.iter()
        .find(|ext| ext.extension_type == 0x0033) // key_share (0x0033)
        .ok_or_else(|| anyhow::anyhow!("No key_share extension"))?;

    // key_share拡張のデータ構造を解析
    let ext_data = &key_share_ext.extension_data;
    
    // 最小長チェック（KeyShareEntryの最小サイズ）
    if ext_data.len() < 2 {
        return Err(anyhow::anyhow!("Invalid key_share extension data: too short"));
    }

    // クライアントの公開鍵リストの長さを取得
    let total_length = ((ext_data[0] as u16) << 8 | ext_data[1] as u16) as usize;
    if total_length + 2 != ext_data.len() {
        return Err(anyhow::anyhow!("Invalid key_share extension data length"));
    }

    // クライアントの公開鍵リストを解析
    let mut offset = 2;  // 長さフィールドの後から開始
    let mut client_public_key = None;

    while offset < ext_data.len() {
        // KeyShareEntryの最小サイズチェック
        if offset + 4 > ext_data.len() {
            return Err(anyhow::anyhow!("Invalid key_share entry: truncated"));
        }

        // KeyShareEntryの構造を解析
        let group_id = (ext_data[offset] as u16) << 8 | ext_data[offset + 1] as u16;
        let key_length = (ext_data[offset + 2] as u16) << 8 | ext_data[offset + 3] as u16;
        offset += 4;

        // 鍵データの長さチェック
        if offset + key_length as usize > ext_data.len() {
            return Err(anyhow::anyhow!("Invalid key_share key length: exceeds data"));
        }

        // サポートされているグループIDのチェック
        match group_id {
            0x001d => { // X25519
                if key_length != 32 {
                    return Err(anyhow::anyhow!("Invalid X25519 key length: expected 32 bytes"));
                }
                let raw_key = &ext_data[offset..offset + key_length as usize];
                
                client_public_key = Some(raw_key.to_vec());
                break;
            }
            _ => {
                // サポートされていないグループIDはスキップ
            }
        }
        offset += key_length as usize;
    }

    let client_public_key = client_public_key.ok_or_else(|| anyhow::anyhow!("No supported key share group found"))?;

    // クライアントの公開鍵を検証
    if !crypto::verify_x25519_public_key(&client_public_key) {
        return Err(anyhow::anyhow!("Invalid X25519 public key"));
    }

    // クライアントの公開鍵をそのまま使用
    let peer_kx = client_public_key;

    // 共有秘密の計算
    let mut shared_secret = Vec::new();
    let _: Result<(), Unspecified> = agreement::agree_ephemeral(
        private_key,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, &peer_kx),
        |km| { 
            shared_secret = km.to_vec(); 
            Ok(()) 
        }
    ).map_err(|e: Unspecified| anyhow::anyhow!("Failed to compute shared secret: {:?}", e))?;

    // 鍵スケジュールの初期化（選択した署名アルゴリズムを使用）
    let mut key_schedule = crypto::KeySchedule::new(
        &shared_secret,
        transcript_hash.as_ref(),
        selected_cipher_suite,
        selected_signature_alg
    ).map_err(|e| anyhow::anyhow!("Failed to initialize key schedule: {}", e))?;

    // EncryptedExtensions
    let mut encrypted_extensions = encrypted_extensions::EncryptedExtensions::new();
    
    // クライアントの拡張に基づいて応答を生成
    for ext in &client_hello.extensions {
        match ext.extension_type {
            0x0029 => { // pre_shared_key
                encrypted_extensions.add_extension(0x0029, vec![]);
            },
            0x002a => { // early_data
                encrypted_extensions.add_extension(0x002a, vec![]);
            },
            0x0031 => { // post_handshake_auth
                encrypted_extensions.add_extension(0x0031, vec![]);
            },
            _ => {
                // サポートされていない拡張はスキップ
            }
        }
    }
    
    let encrypted_extensions_bytes = encrypted_extensions.to_bytes();
    let encrypted_extensions_record = key_schedule.encrypt_handshake(&encrypted_extensions_bytes)?;
    socket.write_all(&encrypted_extensions_record).await?;

    // トランスクリプトハッシュの更新（EncryptedExtensionsを追加）
    let mut handshake_messages = handshake_messages_till_sh.clone();
    handshake_messages.extend_from_slice(&encrypted_extensions_bytes);

    // Certificate
    let (certificate, plain_certificate) = key_schedule.create_certificate()?;
    socket.write_all(&certificate).await?;

    // トランスクリプトハッシュの更新（Certificateを追加）
    handshake_messages.extend_from_slice(&plain_certificate);
    transcript_hash = digest::digest(digest_alg, &handshake_messages);
    
    // CertificateVerify
    let (certificate_verify, plain_certificate_verify) = key_schedule.create_certificate_verify(transcript_hash.as_ref())?;
    socket.write_all(&certificate_verify).await?;
    
    // トランスクリプトハッシュの更新（CertificateVerifyを追加）
    handshake_messages.extend_from_slice(&plain_certificate_verify);
    transcript_hash = digest::digest(digest_alg, &handshake_messages);
    
    // Finished
    let finished = key_schedule.create_finished(transcript_hash.as_ref());
    let encrypted_finished = key_schedule.encrypt_handshake(&finished)?;
    socket.write_all(&encrypted_finished).await?;

    // クライアントのFinishedを待機
    let mut buffer = [0u8; 4096];
    let n = socket.read(&mut buffer).await?;
    let client_finished_record = record::TLSPlaintext::from_bytes(&buffer[..n])
        .ok_or_else(|| anyhow::anyhow!("Invalid record"))?;

    // クライアントのFinishedを復号（レコードヘッダーを除去）
    let client_finished = key_schedule.decrypt_handshake(&client_finished_record.fragment)?;

    // クライアントのFinishedを検証
    let verify_data = key_schedule.verify_data(transcript_hash.as_ref());
    if client_finished[4..] != verify_data {
        return Err(anyhow::anyhow!("Invalid client finished message"));
    }

    // アプリケーションデータの送信
    let application_data = b"Hello, TLS 1.3!";
    let application_data_record = key_schedule.encrypt_application_data(application_data);
    socket.write_all(&application_data_record).await?;

    Ok(())
} 