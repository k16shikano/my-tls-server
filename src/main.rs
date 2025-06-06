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

use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // コマンドライン引数からアドレスとポート番号を取得
    let args: Vec<String> = env::args().collect();
    let (addr, port) = match args.len() {
        1 => ("127.0.0.1".to_string(), 4433),
        2 => ("127.0.0.1".to_string(), args[1].parse::<u16>()
            .map_err(|_| anyhow::anyhow!("Invalid port number"))?),
        3 => (args[1].clone(), args[2].parse::<u16>()
            .map_err(|_| anyhow::anyhow!("Invalid port number"))?),
        _ => return Err(anyhow::anyhow!("Usage: {} [address] [port]", args[0])),
    };

    // TCPリスナーを指定されたアドレスとポートで開始
    let listener = match TcpListener::bind(format!("{}:{}", addr, port)).await {
        Ok(l) => l,
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to start server: {}", e));
        }
    };

    println!("Server listening on {}:{}", addr, port);

    // 接続を継続的に受け付ける
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                println!("New connection from {}", addr);
                // 各接続を新しいタスクで処理
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(socket).await {
                        println!("Error handling connection from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                println!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_connection(mut socket: tokio::net::TcpStream) -> Result<()> {
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

    // サーバーの乱数を生成
    let mut server_random = [0u8; 32];
    rng.fill(&mut server_random)
        .map_err(|e: Unspecified| anyhow::anyhow!("Failed to generate server random: {:?}", e))?;

    // クライアントの暗号スイート提案から適切なものを選択
    let selected_cipher_suite = *client_hello.cipher_suites.iter()
        .find(|&&suite| {
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

    // クライアントのFinishedメッセージを待つ
    let mut buffer = [0u8; 1024];
    let n = socket.read(&mut buffer).await
        .map_err(|e| anyhow::anyhow!("Failed to read from socket: {}", e))?;

    let mut offset = 0;
    while offset < n {
        let record = record::TLSPlaintext::from_bytes(&buffer[offset..n])
            .ok_or_else(|| anyhow::anyhow!("Invalid record"))?;

        match record.content_type {
            record::ContentType::ChangeCipherSpec => {
                offset += record.fragment.len() + 5;
                continue;
            },
            record::ContentType::ApplicationData => {
                // 暗号化されたFinishedメッセージを復号
                let plaintext = key_schedule.decrypt_handshake(&buffer[offset..offset + record.fragment.len() + 5])?;
                // トランスクリプトハッシュの更新（復号化されたFinishedを追加）
                handshake_messages.extend_from_slice(&plaintext);
                key_schedule.increment_sequence_number();
            },
            _ => {
                return Err(anyhow::anyhow!("Unexpected content type: {:?}", record.content_type));
            }
        }

        offset += record.fragment.len() + 5;
    }

    println!("Handshake Finished!!");

    // クライアントからのデータを継続的に待ち受ける
    let mut buffer = [0u8; 4096];
    loop {
        match socket.read(&mut buffer).await {
            Ok(0) => {
                println!("Client closed connection");
                break;
            }
            Ok(n) => {
                println!("Received {} bytes from client", n);
                // 受信したデータを処理
                match key_schedule.decrypt_handshake(&buffer[..n]) {
                    Ok(plaintext) => {
                        println!("Decrypted message: {:02x?}", plaintext);
                    }
                    Err(e) => {
                        println!("Failed to decrypt message: {}", e);
                        break;
                    }
                }
            }
            Err(e) => {
                println!("Error reading from socket: {}", e);
                break;
            }
        }
    }

    Ok(())
} 