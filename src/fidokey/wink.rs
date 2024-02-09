use super::FidoKeyHid;
use crate::ctaphid;
use crate::result::Result;

impl FidoKeyHid {
    /// Lights the LED on the FIDO key
    pub fn wink(&self) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;
        ctaphid::ctaphid_wink(self, &cid)
    }
}
