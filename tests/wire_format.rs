//! Golden wire-format pins for the shared protos.
//!
//! Every internal gRPC caller compiles these `.proto` files independently and
//! is deployed on its own schedule. Two things must therefore never happen:
//!
//!  1. **A field's number changes.** An old client would then send `runner_id`
//!     (field 1) and the new server would read it as `access_token` -- silently.
//!     The RBAC work first shipped exactly that (it renumbered every field to
//!     make room for `access_token = 1`); these tests are why it can't recur.
//!     Legacy bytes must still decode to the same legacy values, with the new
//!     authentication fields empty -- and an *empty* credential is denied
//!     (fail-closed), rather than misparsed.
//!  2. **A new field lands on a number that already meant something**, or on a
//!     `reserved` one.
//!
//! The expected bytes are written out by hand from the protobuf encoding rules
//! (tag = field_number << 3 | wire_type; wire type 2 = length-delimited,
//! 0 = varint), deliberately NOT produced by the code under test.

use ais_proto::accounts as acc;
use ais_proto::secret_service as sec;
use ais_proto::session_manager as sm;
use prost::Message;

/// `field`, length-delimited string.
fn s(tag: u8, value: &str) -> Vec<u8> {
    let mut v = vec![tag, value.len() as u8];
    v.extend_from_slice(value.as_bytes());
    v
}

fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

// ---------------------------------------------------------------------------
// secret.proto
// ---------------------------------------------------------------------------

#[test]
fn secret_create_legacy_bytes_decode_with_empty_auth() {
    // What a pre-RBAC client sends: runner=1 env=2 key=3 value=4 actor=5.
    let old = cat(&[s(0x0a, "r"), s(0x12, "e"), s(0x1a, "k"), s(0x22, "v"), s(0x2a, "a")]);
    let m = sec::CreateSecretRequest::decode(old.as_slice()).unwrap();
    assert_eq!(
        (m.runner_id.as_str(), m.environment_id.as_str(), m.secret_key.as_str(), m.value.as_str(), m.actor.as_str()),
        ("r", "e", "k", "v", "a")
    );
    assert!(m.access_token.is_empty() && m.service_credential.is_empty());
}

#[test]
fn secret_auth_fields_have_pinned_numbers() {
    // Create/Get/Update: access_token = 6, service_credential = 7.
    let want = cat(&[s(0x32, "t"), s(0x3a, "c")]);
    for got in [
        sec::CreateSecretRequest { access_token: "t".into(), service_credential: "c".into(), ..Default::default() }.encode_to_vec(),
        sec::GetSecretRequest { access_token: "t".into(), service_credential: "c".into(), ..Default::default() }.encode_to_vec(),
        sec::UpdateSecretRequest { access_token: "t".into(), service_credential: "c".into(), ..Default::default() }.encode_to_vec(),
    ] {
        assert_eq!(got, want);
    }
    // Delete / GetAll: access_token = 4, service_credential = 5.
    let want = cat(&[s(0x22, "t"), s(0x2a, "c")]);
    assert_eq!(
        sec::DeleteSecretRequest { access_token: "t".into(), service_credential: "c".into(), ..Default::default() }.encode_to_vec(),
        want
    );
    assert_eq!(
        sec::GetAllSecretsRequest { access_token: "t".into(), service_credential: "c".into(), ..Default::default() }.encode_to_vec(),
        want
    );
}

#[test]
fn secret_legacy_fields_keep_their_numbers() {
    // Get: runner=1 env=2 key=3 version=4(varint) actor=5.
    let get = sec::GetSecretRequest::decode(
        cat(&[s(0x0a, "r"), s(0x12, "e"), s(0x1a, "k"), vec![0x20, 7], s(0x2a, "a")]).as_slice(),
    )
    .unwrap();
    assert_eq!((get.runner_id.as_str(), get.secret_key.as_str(), get.version, get.actor.as_str()), ("r", "k", 7, "a"));

    // Update: new_value=4.
    let upd = sec::UpdateSecretRequest::decode(
        cat(&[s(0x0a, "r"), s(0x12, "e"), s(0x1a, "k"), s(0x22, "n"), s(0x2a, "a")]).as_slice(),
    )
    .unwrap();
    assert_eq!((upd.new_value.as_str(), upd.actor.as_str()), ("n", "a"));

    // Delete: runner=1 env=2 key=3.
    let del = sec::DeleteSecretRequest::decode(cat(&[s(0x0a, "r"), s(0x12, "e"), s(0x1a, "k")]).as_slice()).unwrap();
    assert_eq!((del.runner_id.as_str(), del.environment_id.as_str(), del.secret_key.as_str()), ("r", "e", "k"));
    assert!(del.access_token.is_empty() && del.service_credential.is_empty());

    // GetAll: runner=1 env=2 version=3(varint).
    let all = sec::GetAllSecretsRequest::decode(cat(&[s(0x0a, "r"), s(0x12, "e"), vec![0x18, 9]]).as_slice()).unwrap();
    assert_eq!((all.runner_id.as_str(), all.environment_id.as_str(), all.version), ("r", "e", 9));
    assert!(all.access_token.is_empty() && all.service_credential.is_empty());
}

// ---------------------------------------------------------------------------
// session_manager.proto
// ---------------------------------------------------------------------------

#[test]
fn deploy_legacy_bytes_decode_with_empty_auth_and_project() {
    // template_id=1 (optional string), applet_id=5.
    let old = cat(&[s(0x0a, "tpl"), s(0x2a, "applet")]);
    let m = sm::DeployTemplateRequest::decode(old.as_slice()).unwrap();
    assert_eq!(m.template_id.as_deref(), Some("tpl"));
    assert_eq!(m.applet_id, "applet");
    assert!(m.access_token.is_empty() && m.service_credential.is_empty() && m.project_id.is_empty());
}

#[test]
fn deploy_auth_and_project_fields_have_pinned_numbers() {
    // 19 / 20 / 21 -> tags 154 / 162 / 170 as two-byte varints (0x9a 0x01, ...).
    let got = sm::DeployTemplateRequest {
        access_token: "t".into(),
        service_credential: "c".into(),
        project_id: "p".into(),
        ..Default::default()
    }
    .encode_to_vec();
    let want = cat(&[
        vec![0x9a, 0x01, 1, b't'],
        vec![0xa2, 0x01, 1, b'c'],
        vec![0xaa, 0x01, 1, b'p'],
    ]);
    assert_eq!(got, want);
}

#[test]
fn deploy_reserved_field_2_is_never_reused_for_project_id() {
    // Field 2 is `reserved` in DeployTemplateRequest. An older payload that
    // still carries it must not be read as the project.
    let m = sm::DeployTemplateRequest::decode(s(0x12, "x").as_slice()).unwrap();
    assert!(m.project_id.is_empty());
}

#[test]
fn session_requests_keep_legacy_numbers_and_pin_the_new_ones() {
    // GetSession: session_id=1 | access_token=2, service_credential=3.
    let m = sm::GetSessionRequest::decode(s(0x0a, "sid").as_slice()).unwrap();
    assert_eq!(m.session_id, "sid");
    assert!(m.access_token.is_empty() && m.service_credential.is_empty());
    assert_eq!(
        sm::GetSessionRequest { access_token: "t".into(), service_credential: "c".into(), ..Default::default() }.encode_to_vec(),
        cat(&[s(0x12, "t"), s(0x1a, "c")])
    );

    // TerminateSession: session_id=1, force=2(varint) | access_token=3, service_credential=4.
    let m = sm::TerminateSessionRequest::decode(cat(&[s(0x0a, "sid"), vec![0x10, 1]]).as_slice()).unwrap();
    assert_eq!((m.session_id.as_str(), m.force), ("sid", true));
    assert!(m.access_token.is_empty() && m.service_credential.is_empty());
    assert_eq!(
        sm::TerminateSessionRequest { access_token: "t".into(), service_credential: "c".into(), ..Default::default() }.encode_to_vec(),
        cat(&[s(0x1a, "t"), s(0x22, "c")])
    );

    // ListSessions: template_id=1, status=2, page=3, page_size=4 | access_token=5, service_credential=6.
    let m = sm::ListSessionsRequest::decode(cat(&[s(0x0a, "tpl"), vec![0x18, 2], vec![0x20, 50]]).as_slice()).unwrap();
    assert_eq!((m.template_id.as_deref(), m.page, m.page_size), (Some("tpl"), Some(2), Some(50)));
    assert!(m.access_token.is_empty() && m.service_credential.is_empty());
    assert_eq!(
        sm::ListSessionsRequest { access_token: "t".into(), service_credential: "c".into(), ..Default::default() }.encode_to_vec(),
        cat(&[s(0x2a, "t"), s(0x32, "c")])
    );

    // GetSessionLogs: session_id=1, limit=2 | access_token=3, service_credential=4.
    let m = sm::GetSessionLogsRequest::decode(cat(&[s(0x0a, "sid"), vec![0x10, 5]]).as_slice()).unwrap();
    assert_eq!((m.session_id.as_str(), m.limit), ("sid", Some(5)));
    assert_eq!(
        sm::GetSessionLogsRequest { access_token: "t".into(), service_credential: "c".into(), ..Default::default() }.encode_to_vec(),
        cat(&[s(0x1a, "t"), s(0x22, "c")])
    );

    // GetDeployStatus: session_id=1 | access_token=2, service_credential=3.
    let m = sm::GetDeployStatusRequest::decode(s(0x0a, "sid").as_slice()).unwrap();
    assert_eq!(m.session_id, "sid");
    assert_eq!(
        sm::GetDeployStatusRequest { access_token: "t".into(), service_credential: "c".into(), ..Default::default() }.encode_to_vec(),
        cat(&[s(0x12, "t"), s(0x1a, "c")])
    );
}

#[test]
fn report_heartbeat_failure_message_is_pinned() {
    // session_id=1, consecutive_failures=2(varint), last_error=3 (optional).
    let m = sm::ReportHeartbeatFailureRequest::decode(cat(&[s(0x0a, "sid"), vec![0x10, 3], s(0x1a, "boom")]).as_slice()).unwrap();
    assert_eq!((m.session_id.as_str(), m.consecutive_failures, m.last_error.as_deref()), ("sid", 3, Some("boom")));
}

// ---------------------------------------------------------------------------
// accounts.proto (only what RBAC Phases 1/3/4 added or changed)
// ---------------------------------------------------------------------------

#[test]
fn evaluate_service_access_messages_are_pinned() {
    let req = acc::EvaluateServiceAccessRequest {
        raw_credential: "c".into(),
        resource_type: "t".into(),
        resource_id: "i".into(),
        action: "a".into(),
    };
    assert_eq!(req.encode_to_vec(), cat(&[s(0x0a, "c"), s(0x12, "t"), s(0x1a, "i"), s(0x22, "a")]));

    // yes=1(varint), service_name=2, credential_id=3.
    let resp = acc::EvaluateServiceAccessResponse { yes: true, service_name: "n".into(), credential_id: "d".into() };
    assert_eq!(resp.encode_to_vec(), cat(&[vec![0x08, 1], s(0x12, "n"), s(0x1a, "d")]));
}

#[test]
fn service_credential_responses_added_ids_without_moving_anything() {
    // raw_credential=1 (unchanged), credential_id=2 (new).
    let issued = acc::IssueServiceCredentialResponse { raw_credential: "raw".into(), credential_id: "id".into() };
    assert_eq!(issued.encode_to_vec(), cat(&[s(0x0a, "raw"), s(0x12, "id")]));

    // valid=1, organization_id=2, service_name=3 (all unchanged), credential_id=4 (new).
    let legacy = cat(&[vec![0x08, 1], s(0x12, "o"), s(0x1a, "s")]);
    let m = acc::ValidateServiceCredentialResponse::decode(legacy.as_slice()).unwrap();
    assert_eq!((m.valid, m.organization_id.as_str(), m.service_name.as_str()), (true, "o", "s"));
    assert!(m.credential_id.is_empty());
    assert_eq!(
        acc::ValidateServiceCredentialResponse { credential_id: "id".into(), ..Default::default() }.encode_to_vec(),
        s(0x22, "id")
    );
}

#[test]
fn existing_evaluate_access_and_permission_messages_are_unchanged() {
    // PermissionResponse.yes = 1.
    assert_eq!(acc::PermissionResponse { yes: true }.encode_to_vec(), vec![0x08, 1]);
    // EvaluateAccessRequest: claims=1 (map), resource_type=2, resource_id=3, action=4.
    let m = acc::EvaluateAccessRequest::decode(cat(&[s(0x12, "project"), s(0x1a, "abc"), s(0x22, "read")]).as_slice()).unwrap();
    assert_eq!((m.resource_type.as_str(), m.resource_id.as_str(), m.action.as_str()), ("project", "abc", "read"));
}

// ---------------------------------------------------------------------------
// The RPC surface: removing or renaming a method is as breaking as renumbering.
// ---------------------------------------------------------------------------

fn methods(service: &str) -> Vec<String> {
    let set = prost_types::FileDescriptorSet::decode(ais_proto::DESCRIPTOR_SET).unwrap();
    let mut found: Vec<String> = set
        .file
        .iter()
        .flat_map(|f| f.service.iter())
        .filter(|svc| svc.name() == service)
        .flat_map(|svc| svc.method.iter().map(|m| m.name().to_owned()))
        .collect();
    found.sort();
    found
}

#[test]
fn secret_service_rpc_surface_is_pinned() {
    assert_eq!(
        methods("SecretService"),
        ["CreateSecret", "DeleteSecret", "GetAllSecrets", "GetSecret", "UpdateSecret"]
    );
}

#[test]
fn session_manager_rpc_surface_is_pinned() {
    assert_eq!(
        methods("SessionManager"),
        [
            "DeployTemplate",
            "GetCommandMetrics",
            "GetDeployStatus",
            "GetSession",
            "GetSessionLogs",
            "ListSessions",
            // Kaelum has always called this; it must stay in the shared file so
            // its client keeps compiling (RunpodManager answers Unimplemented).
            "ReportHeartbeatFailure",
            "SendHeartbeat",
            "SignalFreeResources",
            "TerminateSession",
        ]
    );
}

#[test]
fn account_internal_keeps_the_rbac_rpcs_and_drops_the_circular_one() {
    let m = methods("AccountInternal");
    for needed in [
        "EvaluateAccess",
        "EvaluateServiceAccess",
        "IssueServiceCredential",
        "ValidateServiceCredential",
        "GrantResourcePermission",
        "GetRunnerOrgId",
        "ValidateToken",
    ] {
        assert!(m.iter().any(|x| x == needed), "AccountInternal lost `{needed}`");
    }
    // ais_auth must not call back into RunpodManager (which calls ais_auth).
    assert!(!m.iter().any(|x| x == "GetSessionProject"));
}
