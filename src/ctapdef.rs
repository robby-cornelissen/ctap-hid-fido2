// Authenticator API
// CTAP 2.0
pub const AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
pub const AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;
pub const AUTHENTICATOR_GET_INFO: u8 = 0x04;
pub const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;

// CTAP 2.1
// 6.7. authenticatorBioEnrollment (0x09)
pub const AUTHENTICATOR_BIO_ENROLLMENT: u8 = 0x09;
// 6.12. Prototype authenticatorBioEnrollment (0x40) (For backwards compatibility with "FIDO_2_1_PRE")
pub const AUTHENTICATOR_BIO_ENROLLMENT_P: u8 = 0x40;

// 6.8. authenticatorCredentialManagement (0x0A)
pub const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x0A;
// 6.13. Prototype authenticatorCredentialManagement (0x41) (For backwards compatibility with "FIDO_2_1_PRE" )
pub const AUTHENTICATOR_CREDENTIAL_MANAGEMENT_P: u8 = 0x41;

pub const AUTHENTICATOR_SELECTION: u8 = 0x0B;
pub const AUTHENTICATOR_LARGEBLOBS: u8 = 0x0C;
pub const AUTHENTICATOR_CONFIG: u8 = 0x0D;

pub(crate) fn get_ctap_last_enroll_sample_status_message(status: u8) -> String {
    match status {
        0x00 => "Good fingerprint capture. 0x00: CTAP2_ENROLL_FEEDBACK_FP_GOOD".to_string(),
        0x01 => "Fingerprint was too high.".to_string(),
        0x02 => "Fingerprint was too low.".to_string(),
        0x03 => "Fingerprint was too left.".to_string(),
        0x04 => "Fingerprint was too right.".to_string(),
        0x05 => "Fingerprint was too fast.".to_string(),
        0x06 => "Fingerprint was too slow.".to_string(),
        0x07 => "Fingerprint was of poor quality.".to_string(),
        0x08 => "Fingerprint was too skewed.".to_string(),
        0x09 => "Fingerprint was too short.".to_string(),
        0x0a => "Merge failure of the capture.".to_string(),
        0x0b => "Fingerprint already exists.".to_string(),
        0x0c => "(this error number is available)".to_string(),
        0x0d => "User did not touch/swipe the authenticator.".to_string(),
        0x0e => "User did not lift the finger off the sensor.".to_string(),
        _ => format!("0x{:X}", status),
    }
}
