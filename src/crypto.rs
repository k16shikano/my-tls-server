use anyhow::Result;
use ring::{
    aead::{LessSafeKey, UnboundKey, Nonce, Aad, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305},
    hkdf::{Salt, HKDF_SHA256, HKDF_SHA384, KeyType},
    digest,
    hmac,
};
use p256::{ecdsa::SigningKey as P256SigningKey, SecretKey as P256SecretKey};
use p384::{ecdsa::SigningKey as P384SigningKey, SecretKey as P384SecretKey};
use p256::ecdsa::signature::Signer as P256Signer;

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
    cipher_suite: &'static ring::aead::Algorithm,
    digest_alg: &'static ring::digest::Algorithm,
    signature_alg: u16,  // 署名アルゴリズム（例：0x0403 for ecdsa_secp256r1_sha256）
    sequence_number: u64,
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
    pub fn new(shared_secret: &[u8], transcript_hash: &[u8], cipher_suite: u16, signature_alg: u16) -> Result<Self> {
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

        Ok(Self {
            early_secret,
            secret_state,
            handshake_secret,
            master_secret,
            client_hs_traffic,
            server_hs_traffic,
            cipher_suite: aead_alg,
            digest_alg,
            signature_alg,
            sequence_number: 0,
        })
    }

    pub fn encrypt_handshake(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // TLSInnerPlaintextの構築
        let mut inner_plaintext = Vec::new();
        inner_plaintext.extend_from_slice(plaintext);
        inner_plaintext.push(0x16);  // content_type (Handshake)
        
        // パディングの追加
        let padding_len = 16 - ((inner_plaintext.len() + 1) % 16);
        inner_plaintext.extend_from_slice(&vec![0x00; padding_len]);

        // encrypted_recordの長さを計算
        let encrypted_record_len = inner_plaintext.len() + self.cipher_suite.tag_len();
        
        // server_handshake_traffic_secretから暗号化キーを導出
        let key_len = self.cipher_suite.key_len();
        let mut key = vec![0u8; key_len];
        
        // HKDF-Expand-Label(server_handshake_traffic_secret, "key", "", key_length)
        let hkdf_alg = if self.cipher_suite == &AES_128_GCM || self.cipher_suite == &CHACHA20_POLY1305 {
            HKDF_SHA256
        } else {
            HKDF_SHA384
        };
        
        // expandの出力長をハッシュ関数の出力長に設定
        let expand_len = hkdf_alg.len();
        let key_label: Vec<&[u8]> = hkdf_label("key", b"", key_len);
        let mut expanded_key = vec![0u8; expand_len];
        let key_prk = ring::hkdf::Prk::new_less_safe(hkdf_alg, &self.server_hs_traffic);
        key_prk.expand(&key_label, hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand key: {}", e))?
            .fill(&mut expanded_key)
            .map_err(|e| anyhow::anyhow!("Failed to fill key: {}", e))?;
        // 必要な長さだけを使用
        key.copy_from_slice(&expanded_key[..key_len]);

        // record_ivの導出
        let mut record_iv = [0u8; 12];
        
        // HKDF-Expand-Label(server_handshake_traffic_secret, "iv", "", iv_length)
        let iv_label = hkdf_label("iv", b"", 12);
        let mut expanded_iv = vec![0u8; expand_len];
        let iv_prk = ring::hkdf::Prk::new_less_safe(hkdf_alg, &self.server_hs_traffic);
        iv_prk.expand(&iv_label, hkdf_alg)
            .map_err(|e| anyhow::anyhow!("Failed to expand iv: {}", e))?
            .fill(&mut expanded_iv)
            .map_err(|e| anyhow::anyhow!("Failed to fill iv: {}", e))?;
        record_iv.copy_from_slice(&expanded_iv[..12]);

        // sequence_numberを8バイトの配列に変換
        let seq_bytes = self.sequence_number.to_be_bytes();

        // nonce = XOR(record_iv, padded_sequence_number)
        let mut nonce = [0u8; 12];
        // 1. sequence_numberを12バイトにパディング（左側に0を埋める）
        let mut padded_seq = [0u8; 12];
        padded_seq[4..].copy_from_slice(&seq_bytes);  // 左側に4バイトの0をパディング
        // 2. record_ivとXOR
        for i in 0..12 {
            nonce[i] = record_iv[i] ^ padded_seq[i];
        }

        // AADの計算（TLSCiphertextのフィールドから）
        let aad = self.compute_aad(0x17, &[0x03, 0x03], encrypted_record_len);

        // 暗号化
        let key = LessSafeKey::new(UnboundKey::new(self.cipher_suite, &key)
            .map_err(|e| anyhow::anyhow!("Failed to create unbound key: {}", e))?);
        
        let nonce = Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|e| anyhow::anyhow!("Failed to create nonce: {}", e))?;
        
        let mut ciphertext = inner_plaintext.clone();
        let tag = key.seal_in_place_separate_tag(nonce, Aad::from(&aad), &mut ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to encrypt: {}", e))?;
        
        // 暗号文と認証タグを結合してencrypted_recordを作成
        let mut encrypted_record = ciphertext;
        encrypted_record.extend_from_slice(tag.as_ref());

        // TLSCiphertextの構築
        let mut tls_ciphertext = Vec::new();
        tls_ciphertext.push(0x17); // application_data
        tls_ciphertext.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        tls_ciphertext.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        tls_ciphertext.extend_from_slice(&encrypted_record);

        // TLSCiphertextの長さを設定
        tls_ciphertext[3] = ((encrypted_record.len() >> 8) & 0xff) as u8;
        tls_ciphertext[4] = (encrypted_record.len() & 0xff) as u8;

        // シーケンス番号をインクリメント
        self.sequence_number += 1;

        Ok(tls_ciphertext)
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
        let key_label = hkdf_label("key", &[], key_len);
        let key_prk = ring::hkdf::Prk::new_less_safe(hkdf_alg_from_suite(0x1302), &self.client_hs_traffic);
        key_prk.expand(&key_label, hkdf_alg_from_suite(0x1302))
            .map_err(|e| anyhow::anyhow!("Failed to expand key: {}", e))?
            .fill(&mut key)
            .map_err(|e| anyhow::anyhow!("Failed to fill key: {}", e))?;

        // 暗号文（認証タグを含む）を取得
        let encrypted_data = &ciphertext[5..5 + record_length];
        let mut plaintext = encrypted_data.to_vec();

        // record_ivの導出
        let mut record_iv = [0u8; 12];
        let iv_label = hkdf_label("iv", &[], 12);
        let mut iv = vec![0u8; 12];
        key_prk.expand(&iv_label[..], hkdf_alg_from_suite(0x1302))
            .map_err(|e| anyhow::anyhow!("Failed to expand iv: {}", e))?
            .fill(&mut iv)
            .map_err(|e| anyhow::anyhow!("Failed to fill iv: {}", e))?;
        record_iv.copy_from_slice(&iv);

        // sequence_numberを8バイトの配列に変換
        let seq_bytes = self.sequence_number.to_be_bytes();

        // nonce = XOR(record_iv, padded_sequence_number)
        let mut nonce = [0u8; 12];
        // 1. sequence_numberを12バイトにパディング（左側に0を埋める）
        let mut padded_seq = [0u8; 12];
        padded_seq[4..].copy_from_slice(&seq_bytes);
        // 2. record_ivとXOR
        for i in 0..12 {
            nonce[i] = record_iv[i] ^ padded_seq[i];
        }

        let aad = self.compute_aad(ciphertext[0], &ciphertext[1..5], record_length);

        // 鍵の作成
        let key = LessSafeKey::new(UnboundKey::new(self.cipher_suite, &key)
            .map_err(|e| anyhow::anyhow!("Failed to create unbound key: {}", e))?);
        
        let nonce = Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|e| anyhow::anyhow!("Failed to create nonce: {}", e))?;

        // 認証タグを検証して復号（ringは自動的に認証タグを検証）
        key.open_in_place(nonce, Aad::from(&aad), &mut plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt: {}", e))?;

        // シーケンス番号をインクリメント
        self.sequence_number += 1;

        Ok(plaintext)
    }

    pub fn encrypt_application_data(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(0x17); // ApplicationData
        record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        record.extend_from_slice(&[0x00, 0x00]); // Length placeholder

        let nonce = self.generate_nonce();
        let aad = self.compute_aad(record[0], &record[1..5], 0);
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
            return Err(anyhow::anyhow!("Invalid ciphertext length in decrypt_application"));
        }

        let nonce = &ciphertext[5..21];
        let aad = self.compute_aad(ciphertext[0], &ciphertext[1..5], ciphertext.len());
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

    pub fn create_certificate(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        // 平文のCertificateメッセージを作成
        let mut plain_message = Vec::new();
        plain_message.push(0x0b); // HandshakeType::Certificate
        plain_message.push(0x00); // length (3 bytes)
        plain_message.push(0x00);
        plain_message.push(0x00);

        // Certificate request context length (0 for server certificates)
        plain_message.push(0x00);

        // Certificate list length (will be updated later)
        let cert_list_start = plain_message.len();
        plain_message.extend_from_slice(&[0x00, 0x00, 0x00]);

        // Certificate entry
        let cert = match self.signature_alg {
            0x0403 => std::fs::read("server.der")
                .map_err(|e| anyhow::anyhow!("Failed to read certificate: {}", e))?,
            0x0503 => std::fs::read("server384.der")
                .map_err(|e| anyhow::anyhow!("Failed to read certificate: {}", e))?,
            _ => std::fs::read("server.der")
                .map_err(|e| anyhow::anyhow!("Failed to read certificate: {}", e))?, // デフォルトはP-256の証明書
        };
        let cert_len = cert.len();

        // Certificate data length (3 bytes)
        plain_message.push(((cert_len >> 16) & 0xff) as u8);
        plain_message.push(((cert_len >> 8) & 0xff) as u8);
        plain_message.push((cert_len & 0xff) as u8);

        // Certificate data
        plain_message.extend_from_slice(&cert);

        // Certificate extensions length (0 for now)
        plain_message.extend_from_slice(&[0x00, 0x00]);

        // Update certificate list length
        let cert_list_len = plain_message.len() - cert_list_start - 3; // Subtract the 3-byte length field itself
        plain_message[cert_list_start] = ((cert_list_len >> 16) & 0xff) as u8;
        plain_message[cert_list_start + 1] = ((cert_list_len >> 8) & 0xff) as u8;
        plain_message[cert_list_start + 2] = (cert_list_len & 0xff) as u8;

        // Update total message length
        let msg_len = plain_message.len() - 4;
        plain_message[1] = ((msg_len >> 16) & 0xff) as u8;
        plain_message[2] = ((msg_len >> 8) & 0xff) as u8;
        plain_message[3] = (msg_len & 0xff) as u8;

        // 暗号化
        let encrypted_message = self.encrypt_handshake(&plain_message)?;

        Ok((encrypted_message, plain_message))
    }

    pub fn create_certificate_verify(&mut self, transcript_hash: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // 平文のCertificateVerifyメッセージを作成
        let mut message = Vec::new();
        message.push(0x0f); // HandshakeType::CertificateVerify
        message.push(0x00); // length (3 bytes)
        message.push(0x00);
        message.push(0x00);

        // 署名アルゴリズムを設定
        message.push((self.signature_alg >> 8) as u8);
        message.push((self.signature_alg & 0xff) as u8);

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
        let encrypted_message = self.encrypt_handshake(&message)?;

        Ok((encrypted_message, message))
    }

    pub fn sign_certificate_verify(&self, transcript_hash: &[u8]) -> Result<Vec<u8>> {
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

        // Sign the content using the selected signature algorithm
        let signature = match self.signature_alg {
            0x0403 => { // ecdsa_secp256r1_sha256
                // Load P-256 private key
                let key_pem = std::fs::read_to_string("server.key")
                    .map_err(|e| anyhow::anyhow!("Failed to read private key: {}", e))?;
                let secret_key = P256SecretKey::from_sec1_pem(&key_pem)
                    .map_err(|e| anyhow::anyhow!("Failed to parse ECDSA private key: {}", e))?;
                let signing_key = P256SigningKey::from(&secret_key);

                // 署名を生成
                let signature: p256::ecdsa::Signature = signing_key.sign(&content);
                signature.to_der().as_bytes().to_vec()
            },
            0x0503 => { // ecdsa_secp384r1_sha384
                // Load P-384 private key
                let key_pem = std::fs::read_to_string("server384.key")
                    .map_err(|e| anyhow::anyhow!("Failed to read private key: {}", e))?;
                let secret_key = P384SecretKey::from_sec1_pem(&key_pem)
                    .map_err(|e| anyhow::anyhow!("Failed to parse ECDSA private key: {}", e))?;
                let signing_key = P384SigningKey::from(&secret_key);

                // 署名を生成
                let signature: p384::ecdsa::Signature = signing_key.sign(&content);
                signature.to_der().as_bytes().to_vec()
            },
            0x0804 => { // rsa_pss_rsae_sha256
                // TODO: RSA-PSSの実装
                return Err(anyhow::anyhow!("RSA-PSS not supported yet"));
            },
            _ => {
                return Err(anyhow::anyhow!("Unsupported signature algorithm: {:04x}", self.signature_alg));
            }
        };

        Ok(signature)
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

        // 鍵の更新
        self.client_hs_traffic = new_client_ap_traffic;
        self.server_hs_traffic = new_server_ap_traffic;

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

        // 鍵の更新
        self.client_hs_traffic = client_ap_traffic;
        self.server_hs_traffic = server_ap_traffic;

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
        nonce.copy_from_slice(&self.server_hs_traffic[..12]);
        nonce
    }

    fn compute_aad(&self, content_type: u8, header: &[u8], ciphertext_len: usize) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.push(content_type);  // レコードタイプ（1バイト）
        aad.extend_from_slice(&header[..2]);  // プロトコルバージョン（2バイト）
        // 暗号文の長さ（2バイト、ビッグエンディアン）
        aad.push((ciphertext_len >> 8) as u8);
        aad.push(ciphertext_len as u8);
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

