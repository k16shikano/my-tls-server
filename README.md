# TLS 1.3 Server

Rustで実装されたTLS 1.3サーバーです。RFC 8446に準拠したTLS 1.3プロトコルでのハンドシェイクに対応しています。

## 機能

- TLS 1.3クライアントとのハンドシェイク
- 以下の暗号スイートをサポート
  - TLS_AES_128_GCM_SHA256 (0x1301)
  - TLS_AES_256_GCM_SHA384 (0x1302)
  - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
- 以下の署名アルゴリズムをサポート
  - ecdsa_secp256r1_sha256 (0x0403)
  - ecdsa_secp384r1_sha384 (0x0503)
  - rsa_pss_rsae_sha256 (0x0804)
- X25519鍵交換
- 複数クライアントの同時接続対応

## 必要条件

- Rust 1.70.0以上
- OpenSSL（証明書生成用）

## 証明書の準備

サーバーを実行する前に、以下のようにして秘密鍵と証明書（DER形式の自己署名証明書）を生成する必要があります。

```bash
# P-256用の証明書と鍵
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -x509 -key server.key -out server.der -outform DER -subj "/CN=localhost"

# P-384用の証明書と鍵
openssl ecparam -name secp384r1 -genkey -noout -out server384.key
openssl req -new -x509 -key server384.key -out server384.der -outform DER -subj "/CN=localhost"
```

## 実行

```bash
cargo run
```

サーバーはデフォルトで`127.0.0.1:4433`でリッスンします。

## テスト

OpenSSLクライアントを使用してテストできます。

```bash
openssl s_client -connect localhost:4433 -tls1_3 -ign_eof -msg -debug -state -trace
```

## 実装の詳細

- `src/main.rs`: メインのサーバー実装
- `src/crypto.rs`: 暗号化関連の実装
- `src/record.rs`: TLSレコードレイヤーの実装
- `src/handshake.rs`: ハンドシェイクメッセージの実装
- `src/server_hello.rs`: ServerHelloメッセージの実装
- `src/encrypted_extensions.rs`: EncryptedExtensionsメッセージの実装

## 注意事項

- この実装は教育目的であり、本番環境での使用は推奨されません
- セキュリティ関連の機能は完全には実装されていません
- エラーハンドリングは基本的な実装のみです
- 暗号化したアプリケーションデータのやり取りはできません

## ライセンス

MITライセンス 
