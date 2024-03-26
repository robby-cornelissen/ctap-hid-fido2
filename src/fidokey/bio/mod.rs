mod bio_enrollment_command;
mod bio_enrollment_params;
mod bio_enrollment_response;

use crate::result::Result;
use crate::token::Token;
use crate::util;
use crate::FidoKeyHid;
use crate::{ctapdef, ctaphid};
pub use bio_enrollment_command::SubCommand as BioCmd;
pub use bio_enrollment_params::*;

impl FidoKeyHid {
    pub fn bio_enrollment_get_fingerprint_sensor_info(
        &self,
        use_preview: bool,
    ) -> Result<BioSensorInfo> {
        let cid = ctaphid::ctaphid_init(self)?;

        // 6.7.2. Get bio modality
        let data1 = self.bio_enrollment(&cid, None, None, use_preview)?;

        if self.enable_log {
            println!("{}", data1);
        }

        // 6.7.3. Get fingerprint sensor info
        let data2 = self.bio_enrollment(
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

    pub fn bio_enrollment_begin(
        &self,
        token: &Token,
        timeout_milliseconds: Option<u16>,
        use_preview: bool,
    ) -> Result<(EnrollStatus1T, EnrollStatus2)> {
        let cid = ctaphid::ctaphid_init(self)?;

        let data = self.bio_enrollment(
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

    pub fn bio_enrollment_next(
        &self,
        token: &Token,
        enroll_status: &EnrollStatus1T,
        timeout_milliseconds: Option<u16>,
        use_preview: bool,
    ) -> Result<EnrollStatus2> {
        let template_info = TemplateInfo::new(&enroll_status.template_id, None);

        let data = self.bio_enrollment(
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

    pub fn bio_enrollment_cancel(
        &self,
        token: &Token,
        enroll_status: &EnrollStatus1T,
        use_preview: bool,
    ) -> Result<()> {
        let data = self.bio_enrollment(
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

    pub fn bio_enrollment_enumerate_enrollments(
        &self,
        token: &Token,
        use_preview: bool,
    ) -> Result<Vec<TemplateInfo>> {
        let cid = ctaphid::ctaphid_init(self)?;

        let data = self.bio_enrollment(
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

    pub fn bio_enrollment_set_friendly_name(
        &self,
        token: &Token,
        template_id: &[u8],
        template_name: &str,
        use_preview: bool,
    ) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;

        let template_info = TemplateInfo::new(template_id, Some(template_name));

        let data = self.bio_enrollment(
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

    pub fn bio_enrollment_remove(
        &self,
        token: &Token,
        template_id: &[u8],
        use_preview: bool,
    ) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;

        let template_info = TemplateInfo::new(template_id, None);
        let data = self.bio_enrollment(
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

    fn bio_enrollment(
        &self,
        cid: &[u8; 4],
        token: Option<&Token>,
        sub_command: Option<bio_enrollment_command::SubCommand>,
        use_preview: bool,
    ) -> Result<BioEnrollmentData> {
        let send_payload =
            bio_enrollment_command::create_payload(token, sub_command, use_preview)?;

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
}
