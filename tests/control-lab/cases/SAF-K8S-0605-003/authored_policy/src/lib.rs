use kubewarden_policy_sdk::{
    accept_request, protocol_version_guest, reject_request, request::ValidationRequest,
    settings::Validatable, validate_settings,
    wapc_guest::{register_function, CallResult},
};
use serde::Deserialize;
use serde_json::Value;

const API_GROUP: &str = "ai.saf-k8s.example";
const API_VERSION: &str = "v1alpha1";
const KIND: &str = "ModelDeployment";
const LABEL: &str = "saf-k8s.example/approved";
const LABEL_VALUE: &str = "yes";

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {}

impl Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> =
        match ValidationRequest::new(payload) {
            Ok(request) => request,
            Err(_) => {
                return reject_request(
                    Some("cannot parse admission request".to_string()),
                    None,
                    None,
                    None,
                )
            }
        };

    let req = &validation_request.request;
    if req.kind.group != API_GROUP || req.kind.version != API_VERSION || req.kind.kind != KIND {
        return accept_request();
    }

    let value = &req.object;
    let label_value = value
        .get("metadata")
        .and_then(|metadata| metadata.get("labels"))
        .and_then(|labels| labels.get(LABEL))
        .and_then(Value::as_str);

    if label_value == Some(LABEL_VALUE) {
        accept_request()
    } else {
        reject_request(
            Some(format!("required label {LABEL} must equal {LABEL_VALUE}")),
            None,
            None,
            None,
        )
    }
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}
