use std::fmt;

pub type Result<T, E=Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CTAP(#[from] CtapError),

    #[error(transparent)]
    U2F(#[from] U2fError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),

    #[error("Unknown error: {0}")]
    Unknown(String)
}

#[derive(thiserror::Error, Debug)]
pub struct CtapError {
    pub code: u8,
    pub name: String,
    pub description: String,
}

impl From<u8> for CtapError {
    fn from(code: u8) -> Self {
        let (name, description) = match code {
            0x00 => ("CTAP1_ERR_SUCCESS", "Indicates successful response."),
            0x01 => ("CTAP1_ERR_INVALID_COMMAND", "The command is not a valid CTAP command."),
            0x02 => ("CTAP1_ERR_INVALID_PARAMETER", "The command included an invalid parameter."),
            0x03 => ("CTAP1_ERR_INVALID_LENGTH", "Invalid message or item length."),
            0x04 => ("CTAP1_ERR_INVALID_SEQ", "Invalid message sequencing."),
            0x05 => ("CTAP1_ERR_TIMEOUT", "Message timed out."),
            0x06 => ("CTAP1_ERR_CHANNEL_BUSY", "Channel busy. Client SHOULD retry the request after a short delay. Note that the client may abort the transaction if the command is no longer relevant."),
            0x0A => ("CTAP1_ERR_LOCK_REQUIRED", "Command requires channel lock."),
            0x0B => ("CTAP1_ERR_INVALID_CHANNEL", "Command not allowed on this cid."),
            0x11 => ("CTAP2_ERR_CBOR_UNEXPECTED_TYPE", "Invalid/unexpected CBOR error."),
            0x12 => ("CTAP2_ERR_INVALID_CBOR", "Error when parsing CBOR."),
            0x14 => ("CTAP2_ERR_MISSING_PARAMETER", "Missing non-optional parameter."),
            0x15 => ("CTAP2_ERR_LIMIT_EXCEEDED", "Limit for number of items exceeded."),
            0x16 => ("CTAP2_ERR_UNSUPPORTED_EXTENSION", "Unsupported extension."),
            0x17 => ("CTAP2_ERR_FP_DATABASE_FULL", "Fingerprint data base is full, e.g., during enrollment."),
            0x18 => ("CTAP2_ERR_LARGE_BLOB_STORAGE_FULL", "Large blob storage is full."),
            0x19 => ("CTAP2_ERR_CREDENTIAL_EXCLUDED", "Valid credential found in the exclude list."),
            0x21 => ("CTAP2_ERR_PROCESSING", "Processing (Lengthy operation is in progress)."),
            0x22 => ("CTAP2_ERR_INVALID_CREDENTIAL", "Credential not valid for the authenticator."),
            0x23 => ("CTAP2_ERR_USER_ACTION_PENDING", "Authentication is waiting for user interaction."),
            0x24 => ("CTAP2_ERR_OPERATION_PENDING", "Processing, lengthy operation is in progress."),
            0x25 => ("CTAP2_ERR_NO_OPERATIONS", "No request is pending."),
            0x26 => ("CTAP2_ERR_UNSUPPORTED_ALGORITHM", "Authenticator does not support requested algorithm."),
            0x27 => ("CTAP2_ERR_OPERATION_DENIED", "Not authorized for requested operation."),
            0x28 => ("CTAP2_ERR_KEY_STORE_FULL", "Internal key storage is full."),
            0x29 => ("CTAP2_ERR_NOT_BUSY", "Authenticator cannot cancel as it is not busy."), // Not in current spec
            0x2A => ("CTAP2_ERR_NO_OPERATION_PENDING", "No outstanding operations."), // Not in current spec
            0x2B => ("CTAP2_ERR_UNSUPPORTED_OPTION", "Unsupported option."),
            0x2C => ("CTAP2_ERR_INVALID_OPTION", "Not a valid option for current operation."),
            0x2D => ("CTAP2_ERR_KEEPALIVE_CANCEL", "Pending keep alive was cancelled."),
            0x2E => ("CTAP2_ERR_NO_CREDENTIALS", "No valid credentials provided."),
            0x2F => ("CTAP2_ERR_USER_ACTION_TIMEOUT", "A user action timeout occurred."),
            0x30 => ("CTAP2_ERR_NOT_ALLOWED", "Continuation command, such as, authenticatorGetNextAssertion not allowed."),
            0x31 => ("CTAP2_ERR_PIN_INVALID", "PIN invalid."),
            0x32 => ("CTAP2_ERR_PIN_BLOCKED", "PIN blocked."),
            0x33 => ("CTAP2_ERR_PIN_AUTH_INVALID", "PIN authentication, pinUvAuthParam, verification failed."),
            0x34 => ("CTAP2_ERR_PIN_AUTH_BLOCKED", "PIN authentication using pinUvAuthToken blocked. Requires power cycle to reset."),
            0x35 => ("CTAP2_ERR_PIN_NOT_SET", "No PIN has been set."),
            0x36 => ("CTAP2_ERR_PIN_REQUIRED", "A pinUvAuthToken is required for the selected operation."),
            0x37 => ("CTAP2_ERR_PIN_POLICY_VIOLATION", "PIN policy violation."),
            0x38 => ("CTAP2_ERR_PIN_TOKEN_EXPIRED", "PIN token expired on authenticator."), // "Reserved for Future Use" in current spec
            0x39 => ("CTAP2_ERR_REQUEST_TOO_LARGE", "Authenticator cannot handle this request due to memory constraints."),
            0x3A => ("CTAP2_ERR_ACTION_TIMEOUT", "The current operation has timed out."),
            0x3B => ("CTAP2_ERR_UP_REQUIRED", "User presence is required for the requested operation."),
            0x3C => ("CTAP2_ERR_UV_BLOCKED", "Built-in user verification is disabled."),
            0x3D => ("CTAP2_ERR_INTEGRITY_FAILURE", "A checksum did not match."),
            0x3E => ("CTAP2_ERR_INVALID_SUBCOMMAND", "The requested subcommand is either invalid or not implemented."),
            0x3F => ("CTAP2_ERR_UV_INVALID", "Built-in user verification unsuccessful. The platform SHOULD retry."),
            0x40 => ("CTAP2_ERR_UNAUTHORIZED_PERMISSION", "The permissions parameter contains an unauthorized permission."),
            0x7F..=0xDE => ("CTAP1_ERR_OTHER", "Other unspecified error."),
            0xDF => ("CTAP2_ERR_SPEC_LAST", "Other unspecified error."),
            0xE0 => ("CTAP2_ERR_EXTENSION_FIRST", "Extension-specific error."),
            0xE1..=0xEE => ("CTAP2_ERR_EXTENSION", "Extension-specific error."),
            0xEF => ("CTAP2_ERR_EXTENSION_LAST", "Extension-specific error."),
            0xF0 => ("CTAP2_ERR_VENDOR_FIRST", "Vendor-specific error."),
            0xF1..=0xFE => ("CTAP2_ERR_VENDOR", "Vendor-specific error."),
            0xFF => ("CTAP2_ERR_VENDOR_LAST", "Vendor-specific error."),
            // Outside of specificiation
            0x6A => ("EXT_BIOPASS_ERR_UNKNOWN", "Feitian BioPass unknown error."),
            _ => ("ERR_UNKNOWN", "Unknown CTAP error"),
        };

        CtapError {
            code,
            name: name.to_string(),
            description: description.to_string()
        }
    }
}

impl fmt::Display for CtapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CTAP error: [0x{:X}, {}, {}]", self.code, self.name, self.description)
    }
}

#[derive(thiserror::Error, Debug)]
pub struct U2fError {
    pub code: u8,
    pub name: String,
    pub description: String,
}

impl From<u8> for U2fError {
    fn from(code: u8) -> Self {
        let (name, description) = match code {
                0x90 => ("SW_NO_ERROR (0x9000)", "The command completed successfully without error."),
                0x69 => ("SW_CONDITIONS_NOT_SATISFIED (0x6985)", "The request was rejected due to test-of-user-presence being required."),
                0x6A => ("SW_WRONG_DATA (0x6A80)", "The request was rejected due to an invalid key handle."),
                0x67 => ("SW_WRONG_LENGTH (0x6700)", "The length of the request was invalid."),
                0x6E => ("SW_CLA_NOT_SUPPORTED (0x6E00)", "The class byte of the request is not supported."),
                0x6D => ("SW_INS_NOT_SUPPORTED (0x6D00)", "The instruction of the request is not supported."),
                _ => ("ERR_UNKNOWN", "Unknown U2F error"),
        };

        U2fError {
            code,
            name: name.to_string(),
            description: description.to_string(),
        }
    }
}

impl fmt::Display for U2fError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "U2F error: [0x{:X}, {}, {}]", self.code, self.name, self.description)
    }
}