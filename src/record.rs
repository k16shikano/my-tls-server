#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[derive(Debug)]
pub struct TLSPlaintext {
    pub content_type: ContentType,
    pub legacy_record_version: [u8; 2],
    pub fragment: Vec<u8>,
}

impl TLSPlaintext {
    pub fn new(content_type: ContentType, fragment: Vec<u8>) -> Self {
        Self {
            content_type,
            legacy_record_version: [0x03, 0x03], // TLS 1.2
            fragment,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.content_type as u8);
        out.extend_from_slice(&self.legacy_record_version);
        out.push((self.fragment.len() >> 8) as u8);
        out.push((self.fragment.len() & 0xff) as u8);
        out.extend_from_slice(&self.fragment);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 {
            println!("Record too short: {} bytes", bytes.len());
            return None;
        }

        let content_type = match bytes[0] {
            0x14 => ContentType::ChangeCipherSpec,
            0x15 => ContentType::Alert,
            0x16 => ContentType::Handshake,
            0x17 => ContentType::ApplicationData,
            _ => {
                println!("Unknown content type: {:02x}", bytes[0]);
                return None;
            }
        };

        let legacy_record_version = [bytes[1], bytes[2]];
        let length = ((bytes[3] as usize) << 8) | (bytes[4] as usize);

        if bytes.len() < 5 + length {
            return None;
        }

        Some(Self {
            content_type,
            legacy_record_version,
            fragment: bytes[5..5 + length].to_vec(),
        })
    }
} 