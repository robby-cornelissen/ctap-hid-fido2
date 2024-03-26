mod bio_enrollment_command;
mod bio_enrollment_params;
mod bio_enrollment_response;

use crate::pintoken::{Permissions, PinToken};
use crate::result::Result;
use crate::token::Token;
use crate::util;
use crate::FidoKeyHid;
use crate::{ctapdef, ctaphid};
pub use bio_enrollment_command::SubCommand as BioCmd;
pub use bio_enrollment_params::*;

use super::pin::DEFAULT_PIN_UV_AUTH_PROTOCOL;

impl FidoKeyHid {
    pub fn bio_enrollment_get_fingerprint_sensor_info_t(
        &self,
        use_preview: bool,
    ) -> Result<BioSensorInfo> {
        let cid = ctaphid::ctaphid_init(self)?;

        // 6.7.2. Get bio modality
        let data1 = self.bio_enrollment_t(&cid, None, None, use_preview)?;

        if self.enable_log {
            println!("{}", data1);
        }

        // 6.7.3. Get fingerprint sensor info
        let data2 = self.bio_enrollment_t(
            &cid,
            None,
            Some(BioCmd::GetFingerprintSensorInfo),
            use_preview,
        )?;

        if self.enable_log {
            println!("{}", data2);
        }

        Ok(BioSensorInfo {
            modality: data1.modality.into(),
            fingerprint_kind: data2.fingerprint_kind.into(),
            max_capture_samples_required_for_enroll: data2.max_capture_samples_required_for_enroll,
            max_template_friendly_name: data2.max_template_friendly_name,
        })
    }

    // TODO remove
    /// BioEnrollment - getFingerprintSensorInfo (CTAP 2.1-PRE)
    pub fn bio_enrollment_get_fingerprint_sensor_info(&self) -> Result<BioSensorInfo> {
        let init = self.bio_enrollment_init(None)?;

        // 6.7.2. Get bio modality
        let data1 = self.bio_enrollment(&init.0, None, None)?;
        if self.enable_log {
            println!("{}", data1);
        }

        // 6.7.3. Get fingerprint sensor info
        let data2 = self.bio_enrollment(&init.0, None, Some(BioCmd::GetFingerprintSensorInfo))?;

        if self.enable_log {
            println!("{}", data2);
        }

        Ok(BioSensorInfo {
            modality: data1.modality.into(),
            fingerprint_kind: data2.fingerprint_kind.into(),
            max_capture_samples_required_for_enroll: data2.max_capture_samples_required_for_enroll,
            max_template_friendly_name: data2.max_template_friendly_name,
        })
    }

    pub fn bio_enrollment_begin_t(
        &self,
        token: &Token,
        timeout_milliseconds: Option<u16>,
        use_preview: bool,
    ) -> Result<(EnrollStatus1T, EnrollStatus2)> {
        let cid = ctaphid::ctaphid_init(self)?;

        let data = self.bio_enrollment_t(
            &cid,
            Some(token),
            Some(BioCmd::EnrollBegin(timeout_milliseconds)),
            use_preview,
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        let result1 = EnrollStatus1T {
            cid,
            template_id: data.template_id.to_vec(),
        };

        let finish = data.last_enroll_sample_status == 0x00 && data.remaining_samples == 0;

        let result2 = EnrollStatus2 {
            status: data.last_enroll_sample_status as u8,
            message: ctapdef::get_ctap_last_enroll_sample_status_message(
                data.last_enroll_sample_status as u8,
            ),
            remaining_samples: data.remaining_samples,
            is_finish: finish,
        };

        Ok((result1, result2))
    }

    // TODO remove
    /// BioEnrollment - EnrollBegin
    pub fn bio_enrollment_begin(
        &self,
        pin: &str,
        timeout_milliseconds: Option<u16>,
    ) -> Result<(EnrollStatus1, EnrollStatus2)> {
        let init = self.bio_enrollment_init(Some(pin))?;

        let data = self.bio_enrollment(
            &init.0,
            init.1.as_ref(),
            Some(BioCmd::EnrollBegin(timeout_milliseconds)),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        let result1 = EnrollStatus1 {
            cid: init.0,
            pin_token: init.1,
            template_id: data.template_id.to_vec(),
        };

        let finish = data.last_enroll_sample_status == 0x00 && data.remaining_samples == 0;
        let result2 = EnrollStatus2 {
            status: data.last_enroll_sample_status as u8,
            message: ctapdef::get_ctap_last_enroll_sample_status_message(
                data.last_enroll_sample_status as u8,
            ),
            remaining_samples: data.remaining_samples,
            is_finish: finish,
        };
        Ok((result1, result2))
    }

    pub fn bio_enrollment_next_t(
        &self,
        token: &Token,
        enroll_status: &EnrollStatus1,
        timeout_milliseconds: Option<u16>,
        use_preview: bool,
    ) -> Result<EnrollStatus2> {
        let template_info = TemplateInfo::new(&enroll_status.template_id, None);

        let data = self.bio_enrollment_t(
            &enroll_status.cid,
            Some(token),
            Some(BioCmd::EnrollCaptureNextSample(
                template_info,
                timeout_milliseconds,
            )),
            use_preview,
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        let finish = data.last_enroll_sample_status == 0x00 && data.remaining_samples == 0;

        let result = EnrollStatus2 {
            status: data.last_enroll_sample_status as u8,
            message: ctapdef::get_ctap_last_enroll_sample_status_message(
                data.last_enroll_sample_status as u8,
            ),
            remaining_samples: data.remaining_samples,
            is_finish: finish,
        };

        Ok(result)
    }

    // TODO remove
    /// BioEnrollment - CaptureNext
    pub fn bio_enrollment_next(
        &self,
        enroll_status: &EnrollStatus1,
        timeout_milliseconds: Option<u16>,
    ) -> Result<EnrollStatus2> {
        let template_info = TemplateInfo::new(&enroll_status.template_id, None);
        let data = self.bio_enrollment(
            &enroll_status.cid,
            enroll_status.pin_token.as_ref(),
            Some(BioCmd::EnrollCaptureNextSample(
                template_info,
                timeout_milliseconds,
            )),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        let finish = data.last_enroll_sample_status == 0x00 && data.remaining_samples == 0;
        let result = EnrollStatus2 {
            status: data.last_enroll_sample_status as u8,
            message: ctapdef::get_ctap_last_enroll_sample_status_message(
                data.last_enroll_sample_status as u8,
            ),
            remaining_samples: data.remaining_samples,
            is_finish: finish,
        };
        Ok(result)
    }

    pub fn bio_enrollment_cancel_t(
        &self,
        token: &Token,
        enroll_status: &EnrollStatus1,
        use_preview: bool,
    ) -> Result<()> {
        let data = self.bio_enrollment_t(
            &enroll_status.cid,
            Some(token),
            Some(BioCmd::CancelCurrentEnrollment),
            use_preview,
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    // TODO remove
    /// BioEnrollment - Cancel current enrollment
    pub fn bio_enrollment_cancel(&self, enroll_status: &EnrollStatus1) -> Result<()> {
        let data = self.bio_enrollment(
            &enroll_status.cid,
            enroll_status.pin_token.as_ref(),
            Some(BioCmd::CancelCurrentEnrollment),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    pub fn bio_enrollment_enumerate_enrollments_t(
        &self,
        token: &Token,
        use_preview: bool,
    ) -> Result<Vec<TemplateInfo>> {
        let cid = ctaphid::ctaphid_init(self)?;

        let data = self.bio_enrollment_t(
            &cid,
            Some(token),
            Some(BioCmd::EnumerateEnrollments),
            use_preview,
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(data.template_infos)
    }

    // TODO remove
    /// BioEnrollment - enumerateEnrollments (CTAP 2.1-PRE)
    /// 6.7.6. Enumerate enrollments
    pub fn bio_enrollment_enumerate_enrollments(&self, pin: &str) -> Result<Vec<TemplateInfo>> {
        let init = self.bio_enrollment_init(Some(pin))?;
        let pin_token = init.1.unwrap();

        let data = self.bio_enrollment(
            &init.0,
            Some(&pin_token),
            Some(BioCmd::EnumerateEnrollments),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(data.template_infos)
    }

    pub fn bio_enrollment_set_friendly_name_t(
        &self,
        token: &Token,
        template_id: &[u8],
        template_name: &str,
        use_preview: bool,
    ) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;

        let template_info = TemplateInfo::new(template_id, Some(template_name));

        let data = self.bio_enrollment_t(
            &cid,
            Some(&token),
            Some(BioCmd::SetFriendlyName(template_info)),
            use_preview,
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    // TODO remove
    /// BioEnrollment - Rename/Set FriendlyName
    /// 6.7.7. Rename/Set FriendlyName
    pub fn bio_enrollment_set_friendly_name(
        &self,
        pin: &str,
        template_id: &[u8],
        template_name: &str,
    ) -> Result<()> {
        let template_info = TemplateInfo::new(template_id, Some(template_name));

        let init = self.bio_enrollment_init(Some(pin))?;
        let pin_token = init.1.unwrap();

        let data = self.bio_enrollment(
            &init.0,
            Some(&pin_token),
            Some(BioCmd::SetFriendlyName(template_info)),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    pub fn bio_enrollment_remove_t(
        &self,
        token: &Token,
        template_id: &[u8],
        use_preview: bool,
    ) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;

        let template_info = TemplateInfo::new(template_id, None);
        let data = self.bio_enrollment_t(
            &cid,
            Some(token),
            Some(BioCmd::RemoveEnrollment(template_info)),
            use_preview,
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    // TODO
    /// 6.7.8. Remove enrollment
    pub fn bio_enrollment_remove(&self, pin: &str, template_id: &[u8]) -> Result<()> {
        let init = self.bio_enrollment_init(Some(pin))?;
        let pin_token = init.1.unwrap();

        let template_info = TemplateInfo::new(template_id, None);
        let data = self.bio_enrollment(
            &init.0,
            Some(&pin_token),
            Some(BioCmd::RemoveEnrollment(template_info)),
        )?;

        if self.enable_log {
            println!("{}", data);
        }

        Ok(())
    }

    fn bio_enrollment_t(
        &self,
        cid: &[u8; 4],
        token: Option<&Token>,
        sub_command: Option<bio_enrollment_command::SubCommand>,
        use_preview: bool,
    ) -> Result<BioEnrollmentData> {
        let send_payload =
            bio_enrollment_command::create_payload_t(token, sub_command, use_preview)?;

        if self.enable_log {
            println!("send(cbor) = {}", util::to_hex_str(&send_payload));
        }

        let response_cbor = ctaphid::ctaphid_cbor(self, cid, &send_payload)?;
        if self.enable_log {
            println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
        }

        let ret = bio_enrollment_response::parse_cbor(&response_cbor)?;
        Ok(ret)
    }

    // TODO remove
    fn bio_enrollment(
        &self,
        cid: &[u8; 4],
        pin_token: Option<&PinToken>,
        sub_command: Option<bio_enrollment_command::SubCommand>,
    ) -> Result<BioEnrollmentData> {
        let send_payload = bio_enrollment_command::create_payload(
            pin_token,
            sub_command,
            true, // TODO function will be removed anyway
                  // self.use_pre_bio_enrollment,
        )?;

        if self.enable_log {
            println!("send(cbor) = {}", util::to_hex_str(&send_payload));
        }

        let response_cbor = ctaphid::ctaphid_cbor(self, cid, &send_payload)?;
        if self.enable_log {
            println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
        }

        let ret = bio_enrollment_response::parse_cbor(&response_cbor)?;
        Ok(ret)
    }

    // TODO remove
    // This needs some review, especially the use of the PIN token
    fn bio_enrollment_init(&self, pin: Option<&str>) -> Result<([u8; 4], Option<PinToken>)> {
        let cid = ctaphid::ctaphid_init(self)?;

        let pin_token = {
            if let Some(pin) = pin {
                // TODO function to be removed anyway
                // if self.use_pre_bio_enrollment {
                if true {
                    Some(self.get_pin_token(DEFAULT_PIN_UV_AUTH_PROTOCOL, pin)?)
                } else {
                    Some(self.get_pin_uv_auth_token(
                        &cid,
                        DEFAULT_PIN_UV_AUTH_PROTOCOL,
                        Some(pin),
                        Permissions::BIO_ENROLLMENT,
                        None,
                    )?)
                }
            } else {
                None
            }
        };

        Ok((cid, pin_token))
    }
}
