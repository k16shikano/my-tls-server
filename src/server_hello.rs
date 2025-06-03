#[derive(Debug)]
pub struct ServerHello {
    // TLS 1.3では、ServerHelloのバージョンは常に0x0303（TLS 1.2）を送信する必要があります
    pub server_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<Extension>,
}

#[derive(Debug)]
pub struct Extension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}

impl ServerHello {
    pub fn new(
        server_version: u16,
        random: [u8; 32],
        session_id: Vec<u8>,
        cipher_suite: u16,
        compression_method: u8,
        extensions: Vec<Extension>,
    ) -> Self {
        let hello = ServerHello {
            server_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        };
        hello
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(0x02); // HandshakeType::ServerHello
        bytes.extend_from_slice(&[0x00, 0x00, 0x00]); // Length placeholder

        // 1. Legacy Version (2 bytes)
        bytes.push((self.server_version >> 8) as u8);
        bytes.push(self.server_version as u8);

        // 2. Random (32 bytes)
        bytes.extend_from_slice(&self.random);

        // 3. Legacy Session ID (1 byte length + variable length)
        bytes.push(self.session_id.len() as u8);
        bytes.extend_from_slice(&self.session_id);

        // 4. Cipher Suite (2 bytes)
        bytes.push((self.cipher_suite >> 8) as u8);
        bytes.push(self.cipher_suite as u8);

        // 5. Legacy Compression Method (1 byte)
        bytes.push(self.compression_method);

        // 6. Extensions (2 bytes length + variable length)
        let mut ext_bytes = Vec::new();
        for ext in &self.extensions {
            ext_bytes.push((ext.extension_type >> 8) as u8);
            ext_bytes.push(ext.extension_type as u8);
            ext_bytes.push((ext.extension_data.len() >> 8) as u8);
            ext_bytes.push(ext.extension_data.len() as u8);
            ext_bytes.extend_from_slice(&ext.extension_data);
        }
        bytes.push((ext_bytes.len() >> 8) as u8);
        bytes.push(ext_bytes.len() as u8);
        bytes.extend_from_slice(&ext_bytes);

        // Fill in the length placeholder
        let length = bytes.len() - 4;
        bytes[1] = ((length >> 16) & 0xff) as u8;
        bytes[2] = ((length >> 8) & 0xff) as u8;
        bytes[3] = (length & 0xff) as u8;

        bytes
    }
} 