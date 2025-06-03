#[derive(Debug)]
pub struct Extension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ClientHello {
    pub legacy_version: [u8; 2],
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 34 {
            return None;
        }

        let mut pos = 0;

        // HandshakeType::ClientHello
        if data[pos] != 0x01 {
            return None;
        }
        pos += 1;

        // メッセージ長（3バイト）
        let msg_len = ((data[pos] as usize) << 16) | ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
        pos += 3;

        if data.len() < pos + msg_len {
            return None;
        }

        // legacy_version
        let legacy_version = [data[pos], data[pos + 1]];
        pos += 2;

        // random
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        // session_id
        let session_id_len = data[pos] as usize;
        pos += 1;
        let session_id = data[pos..pos + session_id_len].to_vec();
        pos += session_id_len;

        // cipher_suites
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let mut cipher_suites = Vec::new();
        for i in 0..cipher_suites_len / 2 {
            let suite = u16::from_be_bytes([data[pos + i * 2], data[pos + i * 2 + 1]]);
            cipher_suites.push(suite);
        }
        pos += cipher_suites_len;

        // compression_methods
        let compression_methods_len = data[pos] as usize;
        pos += 1 + compression_methods_len;

        // extensions
        let mut extensions = Vec::new();
        if pos < data.len() {
            let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let extensions_end = pos + extensions_len;

            while pos < extensions_end {
                let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;

                // key_share拡張の場合、データをそのまま使用
                let ext_data = if ext_type == 0x0033 { // key_share
                    data[pos..pos + ext_len].to_vec()
                } else {
                    data[pos..pos + ext_len].to_vec()
                };
                pos += ext_len;

                extensions.push(Extension {
                    extension_type: ext_type,
                    extension_data: ext_data,
                });
            }
        }

        Some(Self {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            extensions,
        })
    }
} 