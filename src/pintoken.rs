// TODO remove
pub struct PinToken {
    pub key: Vec<u8>,
}

// TODO remove
impl PinToken {
    pub fn new(data: &[u8]) -> PinToken {
        PinToken { key: data.to_vec() }
    }
}

// TODO remove
bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Permissions: u8 {
        const MAKE_CREDENTIAL = 0x01;
        const GET_ASSERTION = 0x02;
        const CREDENTIAL_MANAGEMENT = 0x04;
        const BIO_ENROLLMENT = 0x08;
        const LARGE_BLOB_WRITE = 0x10;
        const AUTHENTICATOR_CONFIGURATION = 0x20;
    }
}