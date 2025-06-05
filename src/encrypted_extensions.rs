#[derive(Debug)]
pub struct EncryptedExtensions {
    extensions: Vec<Extension>,
}

#[derive(Debug)]
pub struct Extension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}

impl EncryptedExtensions {
    pub fn new() -> Self {
        Self {
            extensions: Vec::new(),
        }
    }

    pub fn add_extension(&mut self, extension_type: u16, extension_data: Vec<u8>) {
        println!("Adding extension: type=0x{:04x}, data={:02x?}", extension_type, extension_data);
        self.extensions.push(Extension {
            extension_type,
            extension_data,
        });
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // 拡張データの構築
        let mut extensions_data = Vec::new();
        for ext in &self.extensions {
            extensions_data.extend_from_slice(&ext.extension_type.to_be_bytes());
            extensions_data.extend_from_slice(&(ext.extension_data.len() as u16).to_be_bytes());
            extensions_data.extend_from_slice(&ext.extension_data);
        }
        
        // ハンドシェイクメッセージの構築
        bytes.push(0x08);  // HandshakeType (EncryptedExtensions)
        
        // 拡張データの長さフィールド（2バイト）を含めた全体の長さを設定
        let total_length = extensions_data.len() + 2;  // 拡張データ + 長さフィールド（2バイト）
        bytes.extend_from_slice(&[(total_length >> 16) as u8, (total_length >> 8) as u8, total_length as u8]);  // length
        
        // 拡張データの長さフィールドを追加
        bytes.extend_from_slice(&[(extensions_data.len() >> 8) as u8, extensions_data.len() as u8]);  // extensions length
        bytes.extend_from_slice(&extensions_data);  // extensions data
        
        println!("EncryptedExtensions message: {:02x?}", bytes);
        bytes
    }

    pub fn print_extensions(&self) {
        println!("\n=== EncryptedExtensions Extensions ===");
        for ext in &self.extensions {
            match ext.extension_type {
                0x002b => println!("supported_versions: {:02x?}", ext.extension_data),
                0x000a => println!("supported_groups: {:02x?}", ext.extension_data),
                0x000d => println!("signature_algorithms: {:02x?}", ext.extension_data),
                0x0033 => println!("key_share: {:02x?}", ext.extension_data),
                0x0029 => println!("pre_shared_key: {:02x?}", ext.extension_data),
                0x002a => println!("early_data: {:02x?}", ext.extension_data),
                0x0031 => println!("post_handshake_auth: {:02x?}", ext.extension_data),
                _ => println!("Other extension (0x{:04x}): {:02x?}", ext.extension_type, ext.extension_data),
            }
        }
        println!("=====================================\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_extensions_serialization() {
        let mut ee = EncryptedExtensions::new();
        
        // supported_groups拡張を追加
        ee.add_extension(0x0010, vec![0x00, 0x02, 0x00, 0x1d]); // x25519
        
        // signature_algorithms拡張を追加
        ee.add_extension(0x000d, vec![0x00, 0x04, 0x04, 0x03, 0x08, 0x04]); // ecdsa_secp256r1_sha256
        
        let bytes = ee.to_bytes();
        
        // 基本的な構造の検証
        assert_eq!(bytes[0], 0x08); // EncryptedExtensions
        assert_eq!(bytes.len(), 19); // 1 + 3 + 2 + 13 (拡張データ)
    }
} 