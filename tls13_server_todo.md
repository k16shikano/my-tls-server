# ✅ Goal

Implement a minimal TLS 1.3 server that completes the full handshake and shutdown process, without delivering application data.  
The server will be tested using `openssl s_client` with TLS 1.3.  
External dependencies must be minimized—cryptographic primitives (e.g., HKDF, AES-GCM, X25519) can be borrowed from existing crates if necessary, but protocol logic must be implemented manually.

---

# 📝 TODO List

## 1. TCP Server

- [ ] Start a TCP listener on port 4433.
- [ ] Accept one client and read raw bytes from the socket.

## 2. TLS Record Layer

- [ ] Implement parser and serializer for `TLSPlaintext` and `TLSCiphertext`:

  ```
  struct {
    ContentType type;
    ProtocolVersion legacy_record_version;
    uint16 length;
    opaque fragment[TLSPlaintext.length];
  } TLSPlaintext;
  ```

- [ ] Limit support to `Handshake` (0x16) and `Alert` (0x15) types.

## 3. ClientHello Parsing

- [ ] Parse `ClientHello` structure, including:
  - `legacy_version`, `random`, `session_id`, `cipher_suites`
  - `extensions`, especially:
    - `supported_versions` (must include 0x0304)
    - `key_share` (must include X25519)
    - `supported_groups`
    - `signature_algorithms` (required, but can be ignored)

## 4. Key Exchange & Key Schedule

- [ ] Generate ephemeral X25519 key pair.
- [ ] Derive shared secret from client key.
- [ ] Implement HKDF (RFC 5869).
- [ ] Apply TLS 1.3 key schedule (RFC 8446 §7):
  - Derive handshake traffic keys.
  - Derive `finished_key`.

## 5. ServerHello Construction

- [ ] Construct and send a `ServerHello`:
  - Chosen cipher suite: `TLS_AES_128_GCM_SHA256`
  - Key share extension using server's X25519 public key

## 6. EncryptedExtensions

- [ ] Construct a minimal `EncryptedExtensions` message.
- [ ] Encrypt it using the handshake traffic keys and send it.

## 7. Finished Messages

- [ ] Compute and send the server's `Finished` message.
- [ ] Receive and verify the client's `Finished` message.

## 8. Shutdown

- [ ] Send a `close_notify` alert encrypted with application traffic keys.
- [ ] Close the TCP connection.

## 9. Testing

- [ ] Use `cargo run` to run the server.
- [ ] Use the following command to test the handshake on the other terminal:
  ```
  openssl s_client -connect localhost:4433 -tls1_3 -ign_eof
  ```
- [ ] See server output and fix the server code.
- [ ] Repeat the process until the handshake is successful.

## 10. 現在の作業内容

### 暗号化/復号の問題解決
- [x] server handshake traffic secretを正しく導出
- [ ] Finishedメッセージに対してクライアントからAlertが返るのを解消
- [ ] クライアントからのAlertを復号する


---

# ⚠️ Constraints

- Do not use full TLS libraries (e.g., rustls).
- Use only low-level cryptographic crates (e.g., `ring`) where necessary.
- Prefer manual parsing and message construction.

## 自動テスト手順

1. サーバーの起動とログ出力
   ```powershell
   cargo run > server.log 2>&1
   ```

2. クライアントの接続テスト
   ```powershell
   openssl s_client -connect localhost:4433 -tls1_3 -ign_eof
   ```

3. エラー発生時の対応
   - サーバーログ（server.log）を確認
   - エラーメッセージに基づいて修正
   - 修正後は上記1-2の手順を自動で繰り返し実行
   - ハンドシェイクが成功するまで継続

4. デバッグ出力の活用
   - サーバーログの[DEBUG]タグ付き出力を確認
   - 暗号化パラメータ（key, nonce, AAD等）の値を検証
   - メッセージの長さや構造を確認

5. エラーコードの意味
   - Alert level=2, description=20: bad_record_mac
   - その他のエラーコードはRFC 8446を参照
