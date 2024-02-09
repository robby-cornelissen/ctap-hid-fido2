use crate::result::Result;
use strum::EnumProperty;

pub trait SubCommandBase: EnumProperty {
    fn has_param(&self) -> bool;

    fn id(&self) -> Result<u8> {
        let id_str = self
            .get_str("SubCommandId")
            .ok_or_else(|| anyhow::anyhow!("Err-SubCommandId"))?;
        let id: u8 = String::from(id_str).parse().map_err(anyhow::Error::new)?;
        Ok(id)
    }
}
