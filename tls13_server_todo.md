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

### 暗号化/復号化の問題解決
- [x] `decrypt_handshake`関数の修正
  - [x] AADの長さ計算を修正
  - [x] ContentTypeを0x17（ApplicationData）に変更
- [x] デバッグ出力の追加
  - [x] `encrypt_handshake`と`decrypt_handshake`のデバッグ出力を追加
  - [x] 出力が即時に表示されるように修正
- [ ] クライアントからのFinishedメッセージの復号化に失敗
  - [ ] エラー: "decryption failed or bad record mac"
  - [ ] 原因調査中:
    - [ ] AADの構築が正しく行われているか確認
    - [ ] 鍵の導出が正しく行われているか確認
    - [ ] シーケンス番号の管理が正しいか確認
  - [ ] クライアント側の問題:
    - [ ] クライアントが受信しているメッセージが極端に短い（7バイト）問題の調査
    - [ ] クライアント側の"decryption failed or bad record mac"エラーの原因調査
    - [ ] サーバーから送信した暗号化メッセージが正しくクライアントに届いているか確認
    - [ ] クライアント側のAAD構築とサーバー側のAAD構築が一致しているか確認
    - [ ] デバッグ出力から見つかった問題点:
      - [ ] サーバー側のAAD構築:
        - [ ] EncryptedExtensions: `[17, 03, 03, 00, 07]`（長さが正しいか確認）
        - [ ] Finished: `[17, 03, 03, 00, 25]`（長さが正しいか確認）
      - [ ] 暗号化メッセージの長さ:
        - [ ] EncryptedExtensions: 39バイト（平文6バイト + タグ16バイト + その他）
        - [ ] Finished: 69バイト（平文37バイト + タグ16バイト + その他）
      - [ ] クライアントからの応答:
        - [ ] 受信データ: `[21, 3, 3, 0, 2, 2, 20]`（7バイトのみ）
        - [ ] Alertメッセージ（level=2, description=20）が返ってきている
      - [ ] 暗号化パラメータの詳細:
        - [ ] EncryptedExtensions:
          - [ ] key: `[1b, 11, 83, fc, 41, 02, d0, 76, c2, b3, 72, a2, 8b, d9, 6d, c9]`
          - [ ] nonce: `[4c, 74, 73, 12, ce, 7e, 0a, ac, 0d, 45, 55, 09]`
          - [ ] plaintext+ct: `[08, 00, 00, 05, 00, 00, 16]`
        - [ ] Finished:
          - [ ] key: `[1b, 11, 83, fc, 41, 02, d0, 76, c2, b3, 72, a2, 8b, d9, 6d, c9]`
          - [ ] nonce: `[4c, 74, 73, 12, ce, 7e, 0a, ac, 0d, 45, 55, 08]`
          - [ ] plaintext+ct: `[14, 00, 00, 20, ...]`
      - [ ] 調査が必要な項目:
        - [ ] クライアント側のAAD構築がサーバー側と一致しているか確認
        - [ ] 暗号化キーの導出が正しく行われているか確認
        - [ ] nonceの値が正しく生成・管理されているか確認
        - [ ] メッセージの長さフィールドが正しく設定されているか確認
        - [ ] クライアントが受信した7バイトのデータの意味を解析
        - [ ] Alertメッセージ（level=2, description=20）の具体的な意味を調査
      - [ ] 新たに発見された問題点:
        - [ ] 暗号化キーの不一致:
          - [ ] EncryptedExtensions: `[1b, 11, 83, fc, 41, 02, d0, 76, c2, b3, 72, a2, 8b, d9, 6d, c9]`
          - [ ] Finished: `[f0, 74, 03, 83, e7, 1a, 83, 17, 29, fa, 4a, 20, 94, fc, fd, 42]`
        - [ ] nonceの管理:
          - [ ] EncryptedExtensions: `[4c, 74, 73, 12, ce, 7e, 0a, ac, 0d, 45, 55, 09]`
          - [ ] Finished: `[4c, 74, 73, 12, ce, 7e, 0a, ac, 0d, 45, 55, 08]`
        - [ ] レコードレイヤーの問題:
          - [ ] 受信したAlertメッセージの解析:
            - [ ] content_type: 0x15 (Alert)
            - [ ] legacy_record_version: 0x0303
            - [ ] length: 2
            - [ ] fragment: [0x02, 0x14] (bad_record_mac)
        - [ ] 暗号化メッセージの構造:
          - [ ] EncryptedExtensions:
            - [ ] レコードヘッダー: `[23, 3, 3, 0, 39]`
            - [ ] 暗号文: 39バイト
          - [ ] Finished:
            - [ ] レコードヘッダー: `[23, 3, 3, 0, 69]`
            - [ ] 暗号文: 69バイト
      - [ ] 修正が必要な項目:
        - [ ] 暗号化キーの導出プロセスの確認と修正
        - [ ] nonceの生成と管理方法の修正
        - [ ] AADの構築方法の確認と修正
        - [ ] レコードレイヤーの実装の確認と修正

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
