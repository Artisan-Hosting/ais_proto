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
use ais_proto::billing as bl;
use ais_proto::domains as dom;
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
// billing.proto (BillingAdminService -- plans, subscriptions, invoices, and
// the GPU/LLM prepaid credit ledger)
// ---------------------------------------------------------------------------

#[test]
fn create_or_upgrade_subscription_request_fields_are_pinned() {
    // access_token=1, organization_id=2, storefront=3, plan_code=4,
    // elevated_token=5 -- the field this RPC's whole AUTHZ bar rests on.
    let req = bl::CreateOrUpgradeSubscriptionRequest {
        access_token: "t".into(),
        organization_id: "o".into(),
        storefront: "developer".into(),
        plan_code: "dev_pro".into(),
        elevated_token: "e".into(),
    };
    assert_eq!(
        req.encode_to_vec(),
        cat(&[s(0x0a, "t"), s(0x12, "o"), s(0x1a, "developer"), s(0x22, "dev_pro"), s(0x2a, "e")])
    );
}

#[test]
fn top_up_credit_request_fields_are_pinned() {
    // access_token=1, organization_id=2, amount_cents=3(varint), currency=4,
    // elevated_token=5.
    let req = bl::TopUpCreditRequest {
        access_token: "t".into(),
        organization_id: "o".into(),
        amount_cents: 2500,
        currency: "usd".into(),
        elevated_token: "e".into(),
    };
    assert_eq!(
        req.encode_to_vec(),
        cat(&[s(0x0a, "t"), s(0x12, "o"), vec![0x18, 0xc4, 0x13], s(0x22, "usd"), s(0x2a, "e")])
    );
}

#[test]
fn debit_credit_request_carries_no_end_user_token() {
    // Internal-only RPC: organization_id=1, amount_cents=2(varint),
    // external_reference=3, idempotency_key=4 -- deliberately no
    // access_token/elevated_token field exists on this message at all
    // (see billing.proto's own comment on why -- mTLS-authenticated callers
    // only, matching BillingService's original internal RPCs).
    let req = bl::DebitCreditRequest {
        organization_id: "o".into(),
        amount_cents: 42,
        external_reference: "session-1".into(),
        idempotency_key: "session-1:7".into(),
    };
    assert_eq!(
        req.encode_to_vec(),
        cat(&[s(0x0a, "o"), vec![0x10, 42], s(0x1a, "session-1"), s(0x22, "session-1:7")])
    );
}

#[test]
fn billing_status_enum_discriminants_are_pinned() {
    // The wire value IS the meaning -- reordering these variants would
    // silently reinterpret every stored subscriptions.status row and every
    // value already on the wire.
    assert_eq!(bl::BillingStatus::Unspecified as i32, 0);
    assert_eq!(bl::BillingStatus::Active as i32, 1);
    assert_eq!(bl::BillingStatus::PastDue as i32, 2);
    assert_eq!(bl::BillingStatus::GracePeriod as i32, 3);
    assert_eq!(bl::BillingStatus::Suspended as i32, 4);
    assert_eq!(bl::BillingStatus::Deleted as i32, 5);
}

#[test]
fn subscription_message_fields_are_pinned() {
    let sub = bl::Subscription {
        id: "1".into(),
        organization_id: "o".into(),
        storefront: "developer".into(),
        plan_code: "dev_pro".into(),
        status: bl::BillingStatus::Active as i32,
        current_period_start: 100,
        current_period_end: 200,
        pending_plan_code: "".into(),
        cancel_at_period_end: false,
        created_at: 100,
        updated_at: 100,
    };
    // id=1, organization_id=2, storefront=3, plan_code=4, status=5(varint),
    // current_period_start=6(varint), current_period_end=7(varint),
    // created_at=10(varint), updated_at=11(varint). Default-valued
    // pending_plan_code/cancel_at_period_end (proto3 defaults) are omitted
    // from the wire entirely, not encoded as empty/false.
    assert_eq!(
        sub.encode_to_vec(),
        cat(&[
            s(0x0a, "1"),
            s(0x12, "o"),
            s(0x1a, "developer"),
            s(0x22, "dev_pro"),
            vec![0x28, 1],
            vec![0x30, 100],
            vec![0x38, 0xc8, 0x01],
            vec![0x50, 100],
            vec![0x58, 100],
        ])
    );
}

#[test]
fn credit_balance_fields_are_pinned() {
    // organization_id=1, balance_cents=2(varint), monthly_spend_cap_cents=3(varint).
    let bal = bl::CreditBalance { organization_id: "o".into(), balance_cents: 500, monthly_spend_cap_cents: 10000 };
    assert_eq!(bal.encode_to_vec(), cat(&[s(0x0a, "o"), vec![0x10, 0xf4, 0x03], vec![0x18, 0x90, 0x4e]]));
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

#[test]
fn billing_admin_service_rpc_surface_is_pinned() {
    assert_eq!(
        methods("BillingAdminService"),
        [
            "CancelSubscription",
            "CreateOrUpgradeSubscription",
            "DebitCredit",
            "GetCreditBalance",
            "GetOrganizationBillingStatus",
            "GetSubscription",
            "ListCreditLedger",
            "ListInvoices",
            "ListPlans",
            "ListSubscriptions",
            "PreflightCreditCheck",
            "RecordOverageUsage",
            "RetryInvoicePayment",
            "ScheduleDowngrade",
            "TopUpCredit",
        ]
    );
}

#[test]
fn billing_service_rpc_surface_is_unchanged_by_the_admin_service_addition() {
    // BillingAdminService is a second service in the same file -- confirms
    // the original product-agnostic BillingService's own surface wasn't
    // touched while adding it.
    assert_eq!(
        methods("BillingService"),
        [
            "CancelPaymentIntent",
            "CreatePaymentIntent",
            "GetPaymentIntent",
            "HandleStripeWebhook",
            "RefundPaymentIntent",
            "WatchPaymentIntent",
        ]
    );
}

#[test]
fn get_payment_intent_and_refund_fields_are_pinned() {
    // GetPaymentIntentRequest: id_or_reference=1, include_client_secret=2 (varint).
    let req = bl::GetPaymentIntentRequest { id_or_reference: "r".into(), include_client_secret: true };
    assert_eq!(req.encode_to_vec(), cat(&[s(0x0a, "r"), vec![0x10, 0x01]]));

    // RefundPaymentIntentRequest: id_or_reference=1, reason=2.
    let req = bl::RefundPaymentIntentRequest { id_or_reference: "r".into(), reason: "x".into() };
    assert_eq!(req.encode_to_vec(), cat(&[s(0x0a, "r"), s(0x12, "x")]));

    // RefundPaymentIntentResponse: refund_id=1, status=2, amount_cents=3 (varint).
    let res = bl::RefundPaymentIntentResponse { refund_id: "re".into(), status: "succeeded".into(), amount_cents: 5 };
    assert_eq!(res.encode_to_vec(), cat(&[s(0x0a, "re"), s(0x12, "succeeded"), vec![0x18, 0x05]]));
}

// ---------------------------------------------------------------------------
// domains.proto
// ---------------------------------------------------------------------------

#[test]
fn create_order_request_fields_are_pinned() {
    let bytes = cat(&[
        s(0x0a, "at"),  // access_token = 1
        s(0x12, "q"),   // quote_id = 2
        s(0x1a, "o"),   // organization_id = 3
        s(0x22, "r"),   // runner_id = 4
        s(0x2a, "e"),   // invite_email = 5
        s(0x32, "el"),  // elevated_token = 6
    ]);
    let m = dom::CreateOrderRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(m.access_token, "at");
    assert_eq!(m.quote_id, "q");
    assert_eq!(m.organization_id, "o");
    assert_eq!(m.runner_id, "r");
    assert_eq!(m.invite_email, "e");
    assert_eq!(m.elevated_token, "el");
}

#[test]
fn backend_static_form_fields_are_pinned() {
    // node_id = 1, port = 2 (varint), host = 3, tls = 4, insecure_skip_verify = 5.
    let bytes = cat(&[
        s(0x0a, "n"),
        vec![0x10, 0x50],
        s(0x1a, "h"),
        vec![0x20, 0x01],
        vec![0x28, 0x01],
    ]);
    let m = dom::Backend::decode(bytes.as_slice()).unwrap();
    assert_eq!(m.node_id, "n");
    assert_eq!(m.port, 80);
    assert_eq!(m.host, "h");
    assert!(m.tls);
    assert!(m.insecure_skip_verify);
    // Legacy bytes (node form only) still decode, with the additions unset --
    // an omitted `insecure_skip_verify` must mean "verify".
    let legacy = cat(&[s(0x0a, "n"), vec![0x10, 0x50]]);
    let m = dom::Backend::decode(legacy.as_slice()).unwrap();
    assert!(m.host.is_empty() && !m.tls && !m.insecure_skip_verify);
}

#[test]
fn attach_domain_request_additions_keep_legacy_numbers() {
    // access_token = 1, id_or_fqdn = 2, runner_id = 3, extra_names = 5,
    // no_http_redirect = 6 (varint) -- none moved when 7-9 were appended.
    let bytes = cat(&[
        s(0x0a, "at"),
        s(0x12, "d.example"),
        s(0x1a, "r"),
        s(0x2a, "www.d.example"),
        vec![0x30, 0x01],
    ]);
    let m = dom::AttachDomainRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(m.access_token, "at");
    assert_eq!(m.id_or_fqdn, "d.example");
    assert_eq!(m.runner_id, "r");
    assert_eq!(m.extra_names, ["www.d.example"]);
    assert!(m.no_http_redirect);
    assert!(m.extra_headers.is_empty() && m.cors.is_none() && m.extra_locations.is_empty());
}

#[test]
fn add_domain_and_parent_fqdn_fields_are_pinned() {
    // AddDomainRequest: access_token=1, fqdn=2, organization_id=3, runner_id=4,
    // backends=5, extra_names=6, no_http_redirect=7 (varint).
    let req = dom::AddDomainRequest {
        access_token: "a".into(),
        fqdn: "d.example".into(),
        organization_id: "o".into(),
        runner_id: "r".into(),
        backends: vec![dom::Backend { node_id: "n".into(), port: 80, ..Default::default() }],
        extra_names: vec!["www.d.example".into()],
        no_http_redirect: true,
    };
    let backend = cat(&[s(0x0a, "n"), vec![0x10, 0x50]]);
    assert_eq!(
        req.encode_to_vec(),
        cat(&[
            s(0x0a, "a"),
            s(0x12, "d.example"),
            s(0x1a, "o"),
            s(0x22, "r"),
            vec![0x2a, backend.len() as u8],
            backend,
            s(0x32, "www.d.example"),
            vec![0x38, 0x01],
        ])
    );

    // AddDomainResponse: outcome=3 (varint), notes=4. Appended after
    // required_records=2, so older readers that stop at 2 are unaffected.
    let res = dom::AddDomainResponse {
        outcome: dom::AddDomainOutcome::Provisioned as i32,
        notes: vec!["n".into()],
        ..Default::default()
    };
    assert_eq!(res.encode_to_vec(), cat(&[vec![0x18, 0x03], s(0x22, "n")]));

    // Domain.parent_fqdn = 17 (two-byte tag: 17 << 3 | 2 = 138 -> 0x8a 0x01),
    // InventoryEntry.parent_fqdn = 12 (0x62).
    let d = dom::Domain { parent_fqdn: "p".into(), ..Default::default() };
    assert_eq!(d.encode_to_vec(), cat(&[vec![0x8a, 0x01], vec![1], b"p".to_vec()]));
    let e = dom::InventoryEntry { parent_fqdn: "p".into(), ..Default::default() };
    assert_eq!(e.encode_to_vec(), s(0x62, "p"));
}

#[test]
fn domain_service_rpc_surface_is_pinned() {
    assert_eq!(
        methods("DomainService"),
        [
            "AddDomain",
            "ApplyFreeformVhost",
            "AssignDomain",
            "AttachDomain",
            "ConvertVhost",
            "CreateDnsRecord",
            "CreateOrder",
            "DeleteDnsRecord",
            "DetachDomain",
            "ForceRenew",
            "GetDomain",
            "GetOrder",
            "InviteDomainMember",
            "ListAdoptedVhosts",
            "ListCertificates",
            "ListDnsRecords",
            "ListDomainMembers",
            "ListDomains",
            "ListFindings",
            "ListInventory",
            "ListOrders",
            "ListReleases",
            "PublishNow",
            "QuoteDomain",
            "RemoveDomain",
            "RemoveDomainMember",
            "RescanInventory",
            "SearchDomains",
            "UpdateDnsRecord",
            "ValidateFreeformVhost",
            "VerifyDomainNow",
            "WatchDomain",
        ]
    );
}

#[test]
fn domain_service_no_longer_carries_the_stripe_webhook() {
    // Stripe handling moved to BillingService; Portal calls that one.
    assert!(!methods("DomainService").iter().any(|m| m == "HandleStripeWebhook"));
}
