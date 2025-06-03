#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContentType {
    Invalid = 0,
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

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }

        let content_type = match data[0] {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Invalid,
        };

        if content_type == ContentType::Invalid {
            return None;
        }

        let legacy_record_version = [data[1], data[2]];
        let length = ((data[3] as usize) << 8) | (data[4] as usize);

        if data.len() < 5 + length {
            return None;
        }

        Some(Self {
            content_type,
            legacy_record_version,
            fragment: data[5..5 + length].to_vec(),
        })
    }
} 