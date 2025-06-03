use anyhow::Result;
use ring::{
    aead::{LessSafeKey, UnboundKey, Nonce, Aad, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305},
    hkdf::{Salt, HKDF_SHA256, HKDF_SHA384, KeyType},
    digest,
    hmac,
};
use p256::{ecdsa::SigningKey, SecretKey};
use sha2::{Sha256, Digest};
use p256::ecdsa::signature::Signer;

pub fn hkdf_label<'a>(label: &'a str, context: &'a [u8], len: usize) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let label_bytes = format!("tls13 {}", label);
    
    // ラベルの長さチェック（7-255バイト）
    if label_bytes.len() < 7 || label_bytes.len() > 255 {
        panic!("Label length must be between 7 and 255 bytes");
    }
    
    // コンテキストの長さチェック（0-255バイト）
    if context.len() > 255 {
        panic!("Context length must be between 0 and 255 bytes");
    }
    
    // 出力長（2バイト、ビッグエンディアン）
    let length_bytes = [(len >> 8) as u8, (len & 0xff) as u8];
    let length_bytes = Box::leak(Box::new(length_bytes));
    out.push(&length_bytes[..]);
    
    // ラベル長
    let label_len = [label_bytes.len() as u8];
    let label_len = Box::leak(Box::new(label_len));
    out.push(&label_len[..]);
    
    // ラベル
    let label_bytes = Box::leak(Box::new(label_bytes.into_bytes()));
    out.push(&label_bytes[..]);
    
    // コンテキスト長
    let context_len = [context.len() as u8];
    let context_len = Box::leak(Box::new(context_len));
    out.push(&context_len[..]);
    
    // コンテキスト
    out.push(context);
    
    out
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct KeySchedule {
    early_secret: ring::hkdf::Prk,
    secret_state: Vec<u8>,
    handshake_secret: ring::hkdf::Prk,
    master_secret: Vec<u8>,
    client_hs_traffic: Vec<u8>,
    server_hs_traffic: Vec<u8>,
    client_handshake_iv: [u8; 12],
    server_handshake_iv: [u8; 12],
    cipher_suite: &'static ring::aead::Algorithm,
    client_handshake_seq: u64,
    server_handshake_seq: u64,
    digest_alg: &'static ring::digest::Algorithm,
}

fn aead_alg_from_suite(s: u16) -> &'static ring::aead::Algorithm {
    match s {
        0x1301 => &AES_128_GCM,
        0x1302 => &AES_256_GCM,
        0x1303 => &CHACHA20_POLY1305,
        _      => unreachable!(),
    }
}

pub fn hkdf_alg_from_suite(s: u16) -> ring::hkdf::Algorithm {
    match s {
        0x1301 | 0x1303 => HKDF_SHA256,
        0x1302          => HKDF_SHA384,
        _               => unreachable!(),
    }
}

pub fn digest_alg_from_hkdf(hkdf_alg: ring::hkdf::Algorithm) -> &'static ring::digest::Algorithm {
    if hkdf_alg == HKDF_SHA256 {
        &digest::SHA256
    } else if hkdf_alg == HKDF_SHA384 {
        &digest::SHA384
    } else {
        // デフォルトはSHA256（ありえないはずだが）
        &digest::SHA256
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum RecType {
    Application(Vec<u8>),
    Handshake(Vec<u8>),   // KeyUpdate など
    Alert(Vec<u8>),
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum KeyStage {
    Handshake,
    Application,
}

#[allow(dead_code)]
impl KeySchedule {
    pub fn new(shared_secret: &[u8], transcript_hash: &[u8], cipher_suite: u16) -> Result<Self> {
        let aead_alg = aead_alg_from_suite(cipher_suite);
        let hkdf_alg = hkdf_alg_from_suite(cipher_suite);
        let hash_len = hkdf_alg.len();
        let digest_alg = digest_alg_from_hkdf(hkdf_alg);

        // 1. Early Secretの導出
        let salt_bytes = vec![0u8; hash_len];
        let zeros_salt_bytes = Salt::new(hkdf_alg, &salt_bytes);
        let zeros_ikm_bytes = vec![0u8; hash_len];
        let early_secret = zeros_salt_bytes.extract(&zeros_ikm_bytes);

        // secret_state = HKDF-Expand(early_secret, "derived", Hash(""))
        let empty_hash_digest = digest::digest(digest_alg, b"");
        let empty_hash = empty_hash_digest.as_ref();
        let derived_label = hkdf_label("derived", empty_hash, hash_len);
        //println!("derived_label: {:02x?}", derived_label);           // HKDF-Label の構造
        let mut secret_state = vec![0u8; hash_len];
        early_secret.expand(&derived_label, hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand early secret: {}", e))?
            .fill(&mut secret_state)
            .map_err(|e| anyhow::anyhow!("Failed to fill early secret: {}", e))?;
         
        // 2. Handshake Secretの導出
        let salt = Salt::new(hkdf_alg, &secret_state);
        let handshake_secret = salt.extract(shared_secret);

        // handshake_secretの値を確認
        let mut handshake_secret_bytes = vec![0u8; hash_len];
        handshake_secret.expand(&[b""], hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand handshake secret: {}", e))?
            .fill(&mut handshake_secret_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to fill handshake secret: {}", e))?;

        // 3. Server Handshake Traffic Secretの導出
        let server_hs_traffic_label = hkdf_label("s hs traffic", transcript_hash, hash_len);
        let mut server_hs_traffic = vec![0u8; hash_len];
        handshake_secret.expand(&server_hs_traffic_label, hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand server handshake traffic secret: {}", e))?
            .fill(&mut server_hs_traffic)
            .map_err(|e| anyhow::anyhow!("Failed to fill server handshake traffic secret: {}", e))?;

        println!("server_hs_traffic: {:02x?}", server_hs_traffic);

        // 4. Client Handshake Traffic Secretの導出
        let client_hs_traffic_label = hkdf_label("c hs traffic", transcript_hash, hash_len);
        let mut client_hs_traffic = vec![0u8; hash_len];
        handshake_secret.expand(&client_hs_traffic_label, hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand client handshake traffic secret: {}", e))?
            .fill(&mut client_hs_traffic)
            .map_err(|e| anyhow::anyhow!("Failed to fill client handshake traffic secret: {}", e))?;

        // 5. Master Secretのためのソルトの導出
        let empty_hash_digest = digest::digest(digest_alg, b"");
        let empty_hash = empty_hash_digest.as_ref();
        let master_derived_label = hkdf_label("derived", empty_hash, hash_len);
        let mut master_salt = vec![0u8; hash_len];
        handshake_secret.expand(&master_derived_label, hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand master salt: {}", e))?
            .fill(&mut master_salt)
            .map_err(|e| anyhow::anyhow!("Failed to fill master salt: {}", e))?;

        // Master Secretの導出
        let salt = Salt::new(hkdf_alg, &master_salt);
        let master_secret_prk = salt.extract(&[0u8; 0]);
        let mut master_secret = vec![0u8; hash_len];
        master_secret_prk.expand(&[b""], hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand master secret: {}", e))?
            .fill(&mut master_secret)
            .map_err(|e| anyhow::anyhow!("Failed to fill master secret: {}", e))?;

        // 6. Server Handshake Key/IVの導出
        let server_handshake_key = server_hs_traffic.clone();
        let mut server_handshake_iv = [0u8; 12];
        server_handshake_iv.copy_from_slice(&server_hs_traffic[..12]);

        // 7. Client Handshake Key/IVの導出
        let client_handshake_key = client_hs_traffic.clone();
        let mut client_handshake_iv = [0u8; 12];
        client_handshake_iv.copy_from_slice(&client_hs_traffic[..12]);

        Ok(Self {
            early_secret,
            secret_state,
            handshake_secret,
            master_secret,
            client_hs_traffic,
            server_hs_traffic,
            client_handshake_iv,
            server_handshake_iv,
            cipher_suite: aead_alg,
            client_handshake_seq: 0,
            server_handshake_seq: 0,
            digest_alg,
        })
    }

    pub fn encrypt_handshake(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // レコードヘッダーを作成（長さフィールドは後で設定）
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        record.extend_from_slice(&[0x00, 0x00]); // Length placeholder

        // server_hs_trafficから暗号化キーを導出
        let key_len = self.cipher_suite.key_len();
        let mut key = vec![0u8; key_len];
        key.copy_from_slice(&self.server_hs_traffic[..key_len]);

        // 暗号化
        let nonce = self.generate_nonce();
        let aad = self.compute_aad(record[0], &record[1..5]);
        
        let key = LessSafeKey::new(UnboundKey::new(self.cipher_suite, &key)
            .map_err(|e| anyhow::anyhow!("Failed to create unbound key: {}", e))?);
        
        let nonce = Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|e| anyhow::anyhow!("Failed to create nonce: {}", e))?;
        
        let mut ciphertext = plaintext.to_vec();
        let tag = key.seal_in_place_separate_tag(nonce, Aad::from(&aad), &mut ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to encrypt: {}", e))?;
        
        // 暗号文と認証タグを結合
        ciphertext.extend_from_slice(tag.as_ref());

        // レコードヘッダーの長さを設定（暗号文 + 認証タグの長さ）
        let length = ciphertext.len() as u16;
        record[3] = (length >> 8) as u8;
        record[4] = length as u8;

        // レコードに暗号文を追加
        record.extend_from_slice(&ciphertext);

        // シーケンス番号をインクリメント
        self.server_handshake_seq += 1;

        Ok(record)
    }

    pub fn decrypt_handshake(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // レコードヘッダーの最小長チェック
        if ciphertext.len() < 5 {
            return Err(anyhow::anyhow!("Invalid ciphertext length: too short {}", ciphertext.len()));
        }

        // レコード長の取得
        let record_length = ((ciphertext[3] as usize) << 8) | (ciphertext[4] as usize);
        if ciphertext.len() < 5 + record_length {
            return Err(anyhow::anyhow!("Invalid ciphertext length: record length mismatch"));
        }

        // client_hs_trafficから暗号化キーを導出
        let key_len = self.cipher_suite.key_len();
        let mut key = vec![0u8; key_len];
        key.copy_from_slice(&self.client_hs_traffic[..key_len]);

        // 暗号文（認証タグを含む）を取得
        let encrypted_data = &ciphertext[5..5 + record_length];
        let mut plaintext = encrypted_data.to_vec();

        // ノンスとAADの生成
        let nonce = self.generate_nonce();
        let aad = self.compute_aad(ciphertext[0], &ciphertext[1..5]);

        // 鍵の作成
        let key = LessSafeKey::new(UnboundKey::new(self.cipher_suite, &key)
            .map_err(|e| anyhow::anyhow!("Failed to create unbound key: {}", e))?);
        
        let nonce = Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|e| anyhow::anyhow!("Failed to create nonce: {}", e))?;

        // 認証タグを検証して復号（ringは自動的に認証タグを検証）
        key.open_in_place(nonce, Aad::from(&aad), &mut plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt: {}", e))?;

        // シーケンス番号をインクリメント
        self.client_handshake_seq += 1;

        Ok(plaintext)
    }

    pub fn encrypt_application_data(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(0x17); // ApplicationData
        record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        record.extend_from_slice(&[0x00, 0x00]); // Length placeholder

        let nonce = self.generate_nonce();
        let aad = self.compute_aad(record[0], &record[1..5]);
        let ciphertext = self.encrypt_with_nonce(plaintext, &nonce, &aad).unwrap();

        let length = (ciphertext.len() + 16) as u16; // +16 for auth tag
        record[3] = (length >> 8) as u8;
        record[4] = length as u8;

        record.extend_from_slice(&nonce);
        record.extend_from_slice(&ciphertext);

        record
    }

    pub fn decrypt_application(&self, ciphertext: &[u8]) -> Result<RecType> {
        if ciphertext.len() < 5 {
            return Err(anyhow::anyhow!("Invalid ciphertext length"));
        }

        let nonce = &ciphertext[5..21];
        let aad = self.compute_aad(ciphertext[0], &ciphertext[1..5]);
        let plaintext = self.decrypt_with_nonce(&ciphertext[21..], nonce, &aad)?;

        if plaintext.is_empty() {
            return Err(anyhow::anyhow!("Empty plaintext"));
        }

        match plaintext[0] {
            0x17 => Ok(RecType::Application(plaintext[5..].to_vec())),
            0x15 => Ok(RecType::Alert(plaintext[5..7].try_into().unwrap())),
            0x16 => Ok(RecType::Handshake(plaintext[5..].to_vec())),
            _ => Err(anyhow::anyhow!("Unknown content type: {:02x}", plaintext[0])),
        }
    }

    pub fn create_encrypted_extensions(&mut self) -> Result<Vec<u8>> {
        // 平文のEncryptedExtensionsメッセージを作成
        let mut message = Vec::new();
        message.push(0x08); // HandshakeType::EncryptedExtensions
        message.push(0x00); // length (3 bytes)
        message.push(0x00);
        message.push(0x00);

        // 拡張の長さ（0バイト）
        message.push(0x00);
        message.push(0x00);

        let len = message.len() - 4;
        message[1] = ((len >> 16) & 0xff) as u8;
        message[2] = ((len >> 8) & 0xff) as u8;
        message[3] = (len & 0xff) as u8;

        // 暗号化
        self.encrypt_handshake(&message)
    }

    pub fn create_certificate(&mut self) -> Result<Vec<u8>> {
        // 平文のCertificateメッセージを作成
        let mut message = Vec::new();
        message.push(0x0b); // HandshakeType::Certificate
        message.push(0x00); // length (3 bytes)
        message.push(0x00);
        message.push(0x00);

        // Certificate request context length (0 for server certificates)
        message.push(0x00);

        // Certificate list length (will be updated later)
        let cert_list_start = message.len();
        message.extend_from_slice(&[0x00, 0x00, 0x00]);

        // Certificate entry
        let cert = include_bytes!("../server.der");
        let cert_len = cert.len();

        // Certificate data length (3 bytes)
        message.push(((cert_len >> 16) & 0xff) as u8);
        message.push(((cert_len >> 8) & 0xff) as u8);
        message.push((cert_len & 0xff) as u8);

        // Certificate data
        message.extend_from_slice(cert);

        // Certificate extensions length (0 for now)
        message.extend_from_slice(&[0x00, 0x00]);

        // Update certificate list length
        let cert_list_len = message.len() - cert_list_start - 3; // Subtract the 3-byte length field itself
        message[cert_list_start] = ((cert_list_len >> 16) & 0xff) as u8;
        message[cert_list_start + 1] = ((cert_list_len >> 8) & 0xff) as u8;
        message[cert_list_start + 2] = (cert_list_len & 0xff) as u8;

        // Update total message length
        let msg_len = message.len() - 4;
        message[1] = ((msg_len >> 16) & 0xff) as u8;
        message[2] = ((msg_len >> 8) & 0xff) as u8;
        message[3] = (msg_len & 0xff) as u8;

        // 暗号化
        self.encrypt_handshake(&message)
    }

    pub fn create_certificate_verify(&mut self, transcript_hash: &[u8]) -> Result<Vec<u8>> {
        // 平文のCertificateVerifyメッセージを作成
        let mut message = Vec::new();
        message.push(0x0f); // HandshakeType::CertificateVerify
        message.push(0x00); // length (3 bytes)
        message.push(0x00);
        message.push(0x00);

        // 署名アルゴリズム（ecdsa_secp256r1_sha256）
        message.extend_from_slice(&[0x04, 0x03]);

        // Create the signature
        let signature = self.sign_certificate_verify(transcript_hash)?;

        // 署名の長さ（2 bytes）
        let sig_len = signature.len();
        message.push(((sig_len >> 8) & 0xff) as u8);
        message.push((sig_len & 0xff) as u8);

        // 署名データ
        message.extend_from_slice(&signature);

        // メッセージ長の更新
        let msg_len = message.len() - 4;
        message[1] = ((msg_len >> 16) & 0xff) as u8;
        message[2] = ((msg_len >> 8) & 0xff) as u8;
        message[3] = (msg_len & 0xff) as u8;

        // 暗号化
        self.encrypt_handshake(&message)
    }

    fn sign_certificate_verify(&self, transcript_hash: &[u8]) -> Result<Vec<u8>> {
        // Load private key from server.key file
        let key_pem = std::fs::read_to_string("server.key")
            .map_err(|e| anyhow::anyhow!("Failed to read private key: {}", e))?;

        // Parse the ECDSA private key
        let secret_key = SecretKey::from_sec1_pem(&key_pem)
            .map_err(|e| anyhow::anyhow!("Failed to parse ECDSA private key: {}", e))?;

        let signing_key = SigningKey::from(&secret_key);

        // Create the signature content according to TLS 1.3 spec (RFC 8446 section 4.4.3)
        let mut content = Vec::new();

        // Add the repeated space character (0x20) 64 times
        content.extend_from_slice(&[0x20; 64]);

        // Add the context string "TLS 1.3, server CertificateVerify"
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");

        // Add a single 0x00 byte separator
        content.push(0x00);

        // Add the handshake context (hash of all handshake messages so far)
        content.extend_from_slice(transcript_hash);

        // Hash the content with SHA256
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hasher.finalize();

        // Sign the hash
        let signature: p256::ecdsa::Signature = signing_key.sign(&hash);

        Ok(signature.to_vec())
    }

    pub fn create_finished(&self, transcript_hash: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        message.push(0x14); // HandshakeType::Finished
        message.push(0x00); // length (3 bytes)
        message.push(0x00);
        message.push(0x00);

        // verify_data（32バイト）
        let verify_data = self.verify_data(transcript_hash);
        message.extend_from_slice(&verify_data);

        // メッセージ長の更新
        let msg_len = message.len() - 4;
        message[1] = ((msg_len >> 16) & 0xff) as u8;
        message[2] = ((msg_len >> 8) & 0xff) as u8;
        message[3] = (msg_len & 0xff) as u8;

        message
    }

    pub fn verify_data(&self, transcript_hash: &[u8]) -> Vec<u8> {
        let hkdf_alg = if self.cipher_suite == &AES_128_GCM || self.cipher_suite == &CHACHA20_POLY1305 {
            HKDF_SHA256
        } else {
            HKDF_SHA384
        };
        // server_hs_trafficからPrkを作成
        let prk = ring::hkdf::Prk::new_less_safe(hkdf_alg, &self.server_hs_traffic);
        let finished_label = hkdf_label("finished", &[], hkdf_alg.len());
        let okm = prk
            .expand(&finished_label, hkdf_alg)
            .expect("expand");
        let mut finished_key = vec![0u8; hkdf_alg.len()];
        okm.fill(&mut finished_key).unwrap();

        let hmac_alg = if hkdf_alg == HKDF_SHA256 {
            hmac::HMAC_SHA256
        } else {
            hmac::HMAC_SHA384
        };
        let tag = hmac::sign(&hmac::Key::new(hmac_alg, &finished_key), transcript_hash);
        tag.as_ref().to_vec()
    }

    pub fn update_application_keys(&mut self) -> Result<()> {
        // RFC 8446 §4.6.3 に基づく鍵の更新
        let hkdf_alg = if self.cipher_suite == &AES_128_GCM || self.cipher_suite == &CHACHA20_POLY1305 {
            HKDF_SHA256
        } else {
            HKDF_SHA384
        };

        // 新しいApplication Traffic Secretの導出
        let mut new_client_ap_traffic = vec![0u8; hkdf_alg.len()];
        let client_ap_traffic_label = hkdf_label("c ap traffic", &[], hkdf_alg.len());
        let salt = Salt::new(hkdf_alg, &[]);
        let client_ap_traffic_prk = salt.extract(&self.client_hs_traffic);
        client_ap_traffic_prk.expand(&client_ap_traffic_label[..], hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand new client app traffic: {}", e))?
            .fill(&mut new_client_ap_traffic)
            .map_err(|e| anyhow::anyhow!("Failed to fill new client app traffic: {}", e))?;

        let mut new_server_ap_traffic = vec![0u8; hkdf_alg.len()];
        let server_ap_traffic_label = hkdf_label("s ap traffic", &[], hkdf_alg.len());
        let server_ap_traffic_prk = salt.extract(&self.server_hs_traffic);
        server_ap_traffic_prk.expand(&server_ap_traffic_label[..], hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand new server app traffic: {}", e))?
            .fill(&mut new_server_ap_traffic)
            .map_err(|e| anyhow::anyhow!("Failed to fill new server app traffic: {}", e))?;

        // 新しい鍵とIVの導出
        let key_len = self.cipher_suite.key_len();
        let mut new_client_application_key = vec![0u8; key_len];
        let client_ap_key_label = hkdf_label("key", &[], key_len);
        let client_ap_traffic_prk = salt.extract(&new_client_ap_traffic);
        client_ap_traffic_prk.expand(&client_ap_key_label[..], self.cipher_suite)
            .map_err(|e| anyhow::anyhow!("Failed to expand new client application key: {}", e))?
            .fill(&mut new_client_application_key)
            .map_err(|e| anyhow::anyhow!("Failed to fill new client application key: {}", e))?;

        let mut new_server_application_key = vec![0u8; key_len];
        let server_ap_key_label = hkdf_label("key", b"", key_len);
        let server_ap_traffic_prk = salt.extract(&new_server_ap_traffic);
        server_ap_traffic_prk.expand(&server_ap_key_label[..], self.cipher_suite)
            .map_err(|e| anyhow::anyhow!("Failed to expand new server application key: {}", e))?
            .fill(&mut new_server_application_key)
            .map_err(|e| anyhow::anyhow!("Failed to fill new server application key: {}", e))?;

        // 新しいIVの導出
        let mut tmp = vec![0u8; hkdf_alg.len()];
        let client_ap_iv_label = hkdf_label("iv", b"", 12);
        client_ap_traffic_prk.expand(&client_ap_iv_label[..], hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand new client application iv: {}", e))?
            .fill(&mut tmp)
            .map_err(|e| anyhow::anyhow!("Failed to fill new client application iv: {}", e))?;
        let mut new_client_application_iv = [0u8; 12];
        new_client_application_iv.copy_from_slice(&tmp[..12]);

        let mut tmp = vec![0u8; hkdf_alg.len()];
        let server_ap_iv_label = hkdf_label("iv", b"", 12);
        server_ap_traffic_prk.expand(&server_ap_iv_label[..], hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand new server application iv: {}", e))?
            .fill(&mut tmp)
            .map_err(|e| anyhow::anyhow!("Failed to fill new server application iv: {}", e))?;
        let mut new_server_application_iv = [0u8; 12];
        new_server_application_iv.copy_from_slice(&tmp[..12]);

        // 鍵とIVの更新
        self.client_hs_traffic = new_client_ap_traffic;
        self.server_hs_traffic = new_server_ap_traffic;
        self.client_handshake_iv = new_client_application_iv;
        self.server_handshake_iv = new_server_application_iv;

        // アプリケーション鍵更新時にシーケンス番号をリセット
        self.client_handshake_seq = 0;
        self.server_handshake_seq = 0;

        Ok(())
    }

    pub fn derive_application_traffic_secrets(&mut self, transcript_hash: &[u8]) -> Result<()> {
        let hkdf_alg = if self.cipher_suite == &AES_128_GCM || self.cipher_suite == &CHACHA20_POLY1305 {
            HKDF_SHA256
        } else {
            HKDF_SHA384
        };
        let hash_len = hkdf_alg.len();

        // Application Traffic Secretsの導出
        let mut client_ap_traffic = vec![0u8; hash_len];
        let client_ap_traffic_label = hkdf_label("c ap traffic", transcript_hash, hash_len);
        let salt = Salt::new(hkdf_alg, &[]);
        let client_ap_traffic_prk = salt.extract(&self.client_hs_traffic);
        client_ap_traffic_prk.expand(&client_ap_traffic_label[..], hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand client app traffic: {}", e))?
            .fill(&mut client_ap_traffic)
            .map_err(|e| anyhow::anyhow!("Failed to fill client app traffic: {}", e))?;

        let mut server_ap_traffic = vec![0u8; hash_len];
        let server_ap_traffic_label = hkdf_label("s ap traffic", transcript_hash, hash_len);
        let server_ap_traffic_prk = salt.extract(&self.server_hs_traffic);
        server_ap_traffic_prk.expand(&server_ap_traffic_label[..], hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand server app traffic: {}", e))?
            .fill(&mut server_ap_traffic)
            .map_err(|e| anyhow::anyhow!("Failed to fill server app traffic: {}", e))?;

        // Application Key and IV derivation
        let salt_for_app1 = Salt::new(hkdf_alg, &[]);
        let client_ap_traffic_prk = salt_for_app1.extract(&client_ap_traffic);
        let salt_for_app2 = Salt::new(hkdf_alg, &[]);
        let server_ap_traffic_prk = salt_for_app2.extract(&server_ap_traffic);

        // Client Application Keyの導出
        let key_len = self.cipher_suite.key_len();
        let mut client_application_key = vec![0u8; key_len];
        let client_ap_key_label = hkdf_label("key", b"", key_len);
        client_ap_traffic_prk.expand(&client_ap_key_label[..], self.cipher_suite)
            .map_err(|e| anyhow::anyhow!("Failed to expand client application key: {}", e))?
            .fill(&mut client_application_key)
            .map_err(|e| anyhow::anyhow!("Failed to fill client application key: {}", e))?;

        // Server Application Keyの導出
        let mut server_application_key = vec![0u8; key_len];
        let server_ap_key_label = hkdf_label("key", b"", key_len);
        server_ap_traffic_prk.expand(&server_ap_key_label[..], self.cipher_suite)
            .map_err(|e| anyhow::anyhow!("Failed to expand server application key: {}", e))?
            .fill(&mut server_application_key)
            .map_err(|e| anyhow::anyhow!("Failed to fill server application key: {}", e))?;

        // Client Application IVの導出
        let mut tmp = vec![0u8; hash_len];
        let client_ap_iv_label = hkdf_label("iv", b"", 12);
        client_ap_traffic_prk.expand(&client_ap_iv_label[..], hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand client application iv: {}", e))?
            .fill(&mut tmp)
            .map_err(|e| anyhow::anyhow!("Failed to fill client application iv: {}", e))?;
        let mut client_application_iv = [0u8; 12];
        client_application_iv.copy_from_slice(&tmp[..12]);

        // Server Application IVの導出
        let mut tmp = vec![0u8; hash_len];
        let server_ap_iv_label = hkdf_label("iv", b"", 12);
        server_ap_traffic_prk.expand(&server_ap_iv_label[..], hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand server application iv: {}", e))?
            .fill(&mut tmp)
            .map_err(|e| anyhow::anyhow!("Failed to fill server application iv: {}", e))?;
        let mut server_application_iv = [0u8; 12];
        server_application_iv.copy_from_slice(&tmp[..12]);

        // 鍵とIVの更新
        self.client_hs_traffic = client_application_key;
        self.server_hs_traffic = server_application_key;
        self.client_handshake_iv = client_application_iv;
        self.server_handshake_iv = server_application_iv;

        Ok(())
    }

    pub fn set_write_key(&mut self, stage: KeyStage) -> Result<()> {
        match stage {
            KeyStage::Handshake => {
                // すでにハンドシェイク鍵は設定済み
                Ok(())
            }
            KeyStage::Application => {
                // アプリケーション鍵はderive_application_traffic_secretsで設定済み
                Ok(())
            }
        }
    }

    pub fn set_read_key(&mut self, stage: KeyStage) -> Result<()> {
        match stage {
            KeyStage::Handshake => {
                // すでにハンドシェイク鍵は設定済み
                Ok(())
            }
            KeyStage::Application => {
                // アプリケーション鍵はderive_application_traffic_secretsで設定済み
                Ok(())
            }
        }
    }

    fn generate_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.server_handshake_iv);
        let seq_bytes = self.server_handshake_seq.to_be_bytes();
        
        // 後ろ8バイトとシーケンス番号をXOR
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        
        nonce
    }

    fn compute_aad(&self, content_type: u8, header: &[u8]) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.push(content_type);
        aad.extend_from_slice(header);
        aad
    }

    fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = LessSafeKey::new(UnboundKey::new(self.cipher_suite, &self.server_hs_traffic)
            .map_err(|e| anyhow::anyhow!("Failed to create unbound key: {}", e))?);
        
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|e| anyhow::anyhow!("Failed to create nonce: {}", e))?;
        
        let mut ciphertext = plaintext.to_vec();
        let tag = key.seal_in_place_separate_tag(nonce, Aad::from(aad), &mut ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to encrypt: {}", e))?;
        
        // 暗号文と認証タグを結合
        ciphertext.extend_from_slice(tag.as_ref());
        
        Ok(ciphertext)
    }

    fn decrypt_with_nonce(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = LessSafeKey::new(UnboundKey::new(self.cipher_suite, &self.client_hs_traffic)
            .map_err(|e| anyhow::anyhow!("Failed to create unbound key: {}", e))?);
        
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|e| anyhow::anyhow!("Failed to create nonce: {}", e))?;
        
        // 認証タグの長さを取得
        let tag_len = self.cipher_suite.tag_len();
        if ciphertext.len() < tag_len {
            return Err(anyhow::anyhow!("Ciphertext too short"));
        }
        
        // 暗号文と認証タグを分離
        let (ciphertext_data, _tag) = ciphertext.split_at(ciphertext.len() - tag_len);
        let mut plaintext = ciphertext_data.to_vec();
        
        // 認証タグを検証して復号
        key.open_in_place(nonce, Aad::from(aad), &mut plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt: {}", e))?;
        
        Ok(plaintext)
    }
}

#[allow(dead_code)]
pub fn make_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);
    let seq_bytes = seq.to_be_bytes();
    
    // 後ろ8バイトとシーケンス番号をXOR
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    
    nonce
}

#[allow(dead_code)]
pub fn verify_data(finished_key: &[u8], hash: &[u8]) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, finished_key);
    let tag = ring::hmac::sign(&key, hash);
    tag.as_ref().to_vec()
}

pub fn verify_x25519_public_key(public_key: &[u8]) -> bool {
    // 1. 長さチェック
    if public_key.len() != 32 {
        return false;
    }

    // 2. 0チェック
    let mut is_zero = true;
    for &byte in public_key {
        if byte != 0 {
            is_zero = false;
            break;
        }
    }
    if is_zero {
        return false;
    }

    // 3. 最大値チェック
    let max_value = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    ];
    for i in 0..32 {
        if public_key[i] > max_value[i] {
            return false;
        } else if public_key[i] < max_value[i] {
            break;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use ring::hkdf::{Salt, HKDF_SHA256};
    use anyhow::Result;

    #[test]
    fn test_hkdf_rfc5869_case1() -> Result<()> {
        // Test Case 1: Basic test case with SHA-256
        let ikm = vec![
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
        ];
        let salt = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c
        ];
        let info_bytes = vec![
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9
        ];
        let info = vec![&info_bytes[..]];
        let _expected_prk = vec![
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
            0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
            0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
            0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
        ];
        let expected_okm = vec![
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
            0x58, 0x65
        ];

        // Extract
        let salt = Salt::new(HKDF_SHA256, &salt);
        let prk = salt.extract(&ikm);
        //assert_eq!(prk.as_ref(), expected_prk);

        // Expand
        let mut okm = vec![0u8; 42]; // 出力長を42バイトに変更
        prk.expand(&info, HKDF_SHA256)
            .map_err(|e| anyhow::anyhow!("expand error: {}", e))?
            .fill(&mut okm)
            .map_err(|e| anyhow::anyhow!("fill error: {}", e))?;
        println!("okm: {:02x?}", okm);
        println!("expected_okm: {:02x?}", expected_okm);
        assert_eq!(okm, expected_okm);
        Ok(())
    }
} 

