pub mod make_credential_command;
pub mod make_credential_params;
pub mod make_credential_response;

use super::credential_management::credential_management_params::CredentialProtectionPolicy;
use crate::{ctaphid, result::Result, token::Token, FidoKeyHid};
pub use make_credential_params::{
    Attestation, CredentialSupportedKeyType, Extension, Extension as Mext,
    MakeCredentialArgsBuilderT, MakeCredentialArgsT,
};

impl FidoKeyHid {
    pub fn make_credential_with_args_t(
        &self,
        token: Option<&Token>,
        args: &MakeCredentialArgsT,
    ) -> Result<Attestation> {
        // init
        let cid = ctaphid::ctaphid_init(self)?;

        let user_id = {
            if let Some(rkp) = &args.user_entity {
                rkp.id.to_vec()
            } else {
                [].to_vec()
            }
        };

        // create command
        let send_payload = {
            let mut params =
                make_credential_command::ParamsT::new(&args.rpid, args.challenge.to_vec(), user_id);

            params.option_rk = args.rk.unwrap_or(false);
            params.option_uv = args.uv;
            params.exclude_list = args.exclude_list.to_vec();
            params.key_types = if args.key_types.is_empty() {
                vec![CredentialSupportedKeyType::Ecdsa256]
            } else {
                args.key_types.clone()
            };

            if let Some(user_entity) = &args.user_entity {
                params.user_name = user_entity.name.to_string();
                params.user_display_name = user_entity.display_name.to_string();
            }

            // This is somewhat problematic because the RP entity's ID might conflict with
            // the ID that has already been set on the args.
            if let Some(rp_entity) = &args.rp_entity {
                params.rp_name = rp_entity.name.to_string();
            }

            // TODO
            let extensions = if args.extensions.is_some() {
                Some(args.extensions.as_ref().unwrap())
            } else {
                None
            };

            make_credential_command::create_payload_t(token, params, extensions)
        };

        // send & response
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let attestation = make_credential_response::parse_cbor(&response_cbor)?;
        Ok(attestation)
    }

    pub fn make_credential_t(
        &self,
        token: Option<&Token>,
        rpid: &str,
        challenge: &[u8],
    ) -> Result<Attestation> {
        let builder = MakeCredentialArgsBuilderT::new(rpid, challenge);
        let args = builder.build();

        self.make_credential_with_args_t(token, &args)
    }

    pub fn make_credential_with_key_type_t(
        &self,
        token: Option<&Token>,
        rpid: &str,
        challenge: &[u8],
        key_type: Option<CredentialSupportedKeyType>,
    ) -> Result<Attestation> {
        let mut builder = MakeCredentialArgsBuilderT::new(rpid, challenge);
        if let Some(key_type) = key_type {
            builder = builder.key_type(key_type);
        }
        let args = builder.build();

        self.make_credential_with_args_t(token, &args)
    }

    pub fn make_credential_with_extensions_t(
        &self,
        token: Option<&Token>,
        rpid: &str,
        challenge: &[u8],
        extensions: Option<&Vec<Mext>>,
    ) -> Result<Attestation> {
        let mut builder = MakeCredentialArgsBuilderT::new(rpid, challenge);
        if let Some(extensions) = extensions {
            builder = builder.extensions(extensions);
        }
        let args = builder.build();

        self.make_credential_with_args_t(token, &args)
    }
}
