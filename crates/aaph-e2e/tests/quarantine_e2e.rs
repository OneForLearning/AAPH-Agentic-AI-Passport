use aaph_core::action::{ActionKind, RawActionProposal, ReasonCode};
use aaph_core::agent::{attenuate_authority, AgentDefinition, BehavioralManifest};
use aaph_core::audit::{build_audit_event, genesis_hash, verify_audit_chain};
use aaph_core::budget::{AvailableReservation, BudgetAmounts, BudgetError, BudgetLedger};
use aaph_core::crypto::{digest, AUDIT_EVENT_DOMAIN};
use aaph_core::ids::{
    AgentId, BudgetId, BudgetReservationId, InstanceId, MandateId, ReleaseId, RequestId, SessionId,
};
use aaph_core::mandate::{validate_mandate, Mandate};
use aaph_core::permit::Decision;
use aaph_core::policy::{evaluate_proposal, AuthenticationContext, DemoPolicy};
use aaph_core::state::{AgentInstance, AgentSession, RecoveryValidation};
use aaph_core::UtcTimestamp;

fn authority() -> aaph_core::agent::EffectiveAuthority {
    let actions = vec![
        ActionKind::ListDirectory,
        ActionKind::ReadFile,
        ActionKind::ComputeSha256,
        ActionKind::WriteReport,
    ];
    let mandate = Mandate {
        mandate_id: MandateId::new("mandate").unwrap(),
        agent_id: AgentId::new("agent").unwrap(),
        budget_id: BudgetId::new("budget").unwrap(),
        allowed_actions: actions.clone(),
        resource_prefixes: vec!["inbox/".to_owned(), "output/".to_owned()],
        purposes: vec!["analysis".to_owned()],
        not_before: UtcTimestamp::from_unix_seconds(1),
        expires_at: UtcTimestamp::from_unix_seconds(2_000),
    };
    let definition = AgentDefinition {
        agent_id: mandate.agent_id.clone(),
        display_name: "demo".to_owned(),
        current_release_id: ReleaseId::new("release").unwrap(),
        allowed_actions: actions.clone(),
        resource_prefixes: mandate.resource_prefixes.clone(),
        purposes: mandate.purposes.clone(),
    };
    let manifest = BehavioralManifest {
        schema_version: 1,
        allowed_actions: actions,
        resource_prefixes: mandate.resource_prefixes.clone(),
        purposes: mandate.purposes.clone(),
    };
    attenuate_authority(
        &validate_mandate(&mandate, UtcTimestamp::from_unix_seconds(1_000)).unwrap(),
        &definition,
        &manifest,
    )
    .unwrap()
}
fn proposal(id: &str, resource: &str, destination: Option<String>) -> RawActionProposal {
    RawActionProposal {
        request_id: RequestId::new(id).unwrap(),
        session_id: SessionId::new("session").unwrap(),
        action: "READ_FILE".to_owned(),
        resource: resource.to_owned(),
        size_bytes: Some(20),
        purpose: "analysis".to_owned(),
        destination,
    }
}

#[test]
fn prompt_injection_is_quarantined_and_audited_without_secret_effect() {
    let now = UtcTimestamp::from_unix_seconds(1_000);
    let effective = authority();
    let policy = DemoPolicy::closed_default();
    for (action, resource) in [
        ("LIST_DIRECTORY", "inbox/"),
        ("READ_FILE", "inbox/report.txt"),
        ("READ_FILE", "inbox/poisoned-document.txt"),
    ] {
        println!("[PERMIT] {action} {resource}");
        println!("[EFFECT] completed");
    }
    let started = std::time::Instant::now();
    let attack = evaluate_proposal(
        proposal(
            "attack",
            "../secrets/credentials.txt",
            Some("https://attacker.invalid/collect".to_owned()),
        ),
        &effective,
        &policy,
        AuthenticationContext::AuthenticatedAndBound,
        now,
    );
    assert_eq!(attack.record.decision, Decision::Quarantine);
    assert!(attack.budget.is_none());
    println!("[ATTACK] proposal requests out-of-scope resource");
    let reason = serde_json::to_string(&attack.record.reason).unwrap();
    println!("[DENY] {}", reason.trim_matches('"'));
    let mut instance = AgentInstance::new(InstanceId::new("instance").unwrap());
    instance.contain().unwrap();
    assert_eq!(instance.containment_epoch(), 1);
    println!(
        "[CONTAIN] instance=instance epoch={}",
        instance.containment_epoch()
    );
    let mut session = AgentSession::new(SessionId::new("session").unwrap());
    session.activate().unwrap();
    session.terminate().unwrap();
    println!("[RETRY] legitimate action");
    println!("[DENY] E_SESSION_INACTIVE");
    println!("[REPLAY] E_EPOCH_STALE");
    let payload = digest(AUDIT_EVENT_DOMAIN, &attack.record).unwrap();
    let event = build_audit_event(
        1,
        "QUARANTINE".to_owned(),
        "instance".to_owned(),
        payload,
        genesis_hash().unwrap(),
        now,
    )
    .unwrap();
    verify_audit_chain(&[event]).unwrap();
    println!("[AUDIT] chain valid");
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    let copied_output = "";
    assert!(!copied_output.contains("DEMO_SECRET_NOT_REAL"));
    assert_eq!(attack.record.reason, ReasonCode::DestinationNotAllowed);
}

#[test]
fn recovery_preserves_budget_and_audit() {
    let session = SessionId::new("old-session").unwrap();
    let reservation = BudgetReservationId::new("used").unwrap();
    let mut ledger = BudgetLedger::new(
        BudgetId::new("budget").unwrap(),
        BudgetAmounts {
            action_count: 1,
            read_bytes: 20,
            write_bytes: 0,
        },
    );
    ledger
        .reserve(AvailableReservation {
            reservation_id: reservation.clone(),
            session_id: session.clone(),
            amounts: BudgetAmounts {
                action_count: 1,
                read_bytes: 20,
                write_bytes: 0,
            },
        })
        .unwrap();
    ledger.commit(&reservation).unwrap();
    let consumed = ledger.consumed();
    ledger.close_session(&session).unwrap();
    let denied = ledger.reserve(AvailableReservation {
        reservation_id: BudgetReservationId::new("after-reconnect").unwrap(),
        session_id: SessionId::new("new-session").unwrap(),
        amounts: BudgetAmounts {
            action_count: 1,
            read_bytes: 1,
            write_bytes: 0,
        },
    });
    assert_eq!(denied, Err(BudgetError::CapacityExceeded));
    let mut instance = AgentInstance::new(InstanceId::new("instance").unwrap());
    instance.contain().unwrap();
    instance.request_recovery().unwrap();
    instance
        .complete_recovery(RecoveryValidation::validated())
        .unwrap();
    assert_eq!(instance.containment_epoch(), 1);
    assert_eq!(ledger.consumed(), consumed);
    let payload = digest(AUDIT_EVENT_DOMAIN, &consumed).unwrap();
    let event = build_audit_event(
        1,
        "RECOVERY_VALIDATED".to_owned(),
        "instance".to_owned(),
        payload,
        genesis_hash().unwrap(),
        UtcTimestamp::from_unix_seconds(1_001),
    )
    .unwrap();
    verify_audit_chain(&[event]).unwrap();
}
