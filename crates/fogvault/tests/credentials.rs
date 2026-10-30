//! Public lifecycle proofs for header-only credential mutations.
use fogvault::{
    AuditRequest, CredentialPlan, Engine, Error, KdfPolicy, KdfProfile, Limits, NodeHash,
    NodeStore, Phase, RecordId, Result,
};
use std::collections::BTreeMap;
const OLD: &[u8] = b"old synthetic passphrase";
const NEW: &[u8] = b"new synthetic passphrase";
const ID: RecordId = [7; 16];
#[derive(Clone, Default)]
struct Store {
    descriptor: Vec<u8>,
    head: Vec<u8>,
    nodes: BTreeMap<NodeHash, Vec<u8>>,
    records: BTreeMap<RecordId, (u64, Vec<u8>)>,
}
impl NodeStore for Store {
    fn get(&mut self, h: &NodeHash) -> Result<Option<Vec<u8>>> {
        Ok(self.nodes.get(h).cloned())
    }
    fn put(&mut self, h: NodeHash, b: &[u8]) -> Result<()> {
        if self.nodes.get(&h).is_some_and(|old| old != b) {
            return Err(Error::Integrity);
        }
        self.nodes.insert(h, b.to_vec());
        Ok(())
    }
}
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 4096,
        max_metadata_bytes: 128,
        max_records: 8,
    }
}
fn target() -> KdfProfile {
    let b = KdfProfile::baseline();
    KdfProfile::argon2id(b.memory_kib(), b.passes() + 1).unwrap()
}
fn policy() -> KdfPolicy {
    KdfPolicy::new(vec![KdfProfile::baseline(), target()]).unwrap()
}
fn create() -> (Engine, Store) {
    let mut e = Engine::create_with_kdf_policy(OLD, limits(), policy()).unwrap();
    e.activate_created().unwrap();
    let mut s = Store {
        descriptor: e.descriptor_bytes().to_vec(),
        head: e.head_bytes().to_vec(),
        ..Store::default()
    };
    let p = e
        .prepare_save(
            &mut s,
            ID,
            None,
            b"private label",
            b"opaque consumer bundle",
            [9; 16],
            None,
        )
        .unwrap();
    s.head = p.head_bytes.clone();
    s.records.insert(ID, (p.revision, p.envelope));
    e.confirm_commit(&s.head).unwrap();
    (e, s)
}
fn persist(s: &mut Store, p: &CredentialPlan) {
    s.descriptor = p.descriptor_bytes.clone();
    s.head = p.head_bytes.clone();
}
fn audit(e: &mut Engine, s: &Store) -> Result<()> {
    loop {
        match e.audit_next()? {
            AuditRequest::Node(h) => e.supply_node(s.nodes.get(&h).ok_or(Error::Integrity)?)?,
            AuditRequest::Record { id, .. } => {
                let (v, b) = s.records.get(&id).ok_or(Error::Integrity)?;
                e.supply_record(*v, b.len() as u64, Some(b))?;
            }
            AuditRequest::Done => break,
        }
    }
    e.finish_audit(s.records.len() as u64, s.nodes.len() as u64)?;
    Ok(())
}
fn read(e: &Engine, s: &mut Store) -> Result<Vec<u8>> {
    let p = e.lookup(s, &ID)?;
    let (v, b) = &s.records[&ID];
    Ok(e.read_verified(p.entry().ok_or(Error::NotFound)?, *v, b)?
        .payload
        .to_vec())
}
fn unlock(e: &mut Engine, s: &Store, pw: &[u8]) {
    e.begin_unlock(pw).unwrap();
    e.begin_audit(&s.head).unwrap();
    audit(e, s).unwrap();
    e.activate_audit().unwrap();
}
#[test]
fn portable_credentials_preserve_records_and_revoke_old_authority() {
    let (mut e, mut s) = create();
    let unchanged = s.clone();
    let old = e.current_session().unwrap();
    let proof = e.lookup(&mut s, &ID).unwrap();
    let delayed = e
        .draft_save([8; 16], None, b"", b"delayed", [10; 16])
        .unwrap();
    let draft = e.draft_password_change(OLD, NEW, [11; 16]).unwrap();
    let p = e.stage_credential_change(&draft).unwrap();
    assert_eq!(e.phase(), Phase::Prepared);
    assert_eq!(e.descriptor_bytes(), unchanged.descriptor);
    assert_eq!(e.current_session().unwrap(), old);
    assert_eq!(p.receipt.generation, 2);
    assert!(matches!(
        e.confirm_commit(&p.head_bytes),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        e.confirm_credential_commit(&unchanged.descriptor, &p.head_bytes),
        Err(Error::Integrity)
    ));
    assert_eq!(e.phase(), Phase::Prepared);
    persist(&mut s, &p);
    let done = e.confirm_credential_commit(&s.descriptor, &s.head).unwrap();
    assert_eq!(done.receipt, p.receipt);
    assert!(matches!(e.check_session(&old), Err(Error::StaleSession)));
    assert_eq!(s.records, unchanged.records);
    assert_eq!(s.nodes, unchanged.nodes);
    assert_ne!(s.descriptor, unchanged.descriptor);
    let (v, b) = &s.records[&ID];
    assert!(matches!(
        e.read_verified(proof.entry().unwrap(), *v, b),
        Err(Error::StaleSession)
    ));
    let fresh = e.lookup(&mut s, &[8; 16]).unwrap();
    assert!(matches!(
        e.stage_save(&delayed, fresh, None, &mut s),
        Err(Error::StaleSession)
    ));
    assert_eq!(read(&e, &mut s).unwrap(), b"opaque consumer bundle");
    e.lock();
    assert!(e.begin_unlock(OLD).is_err());
    assert_eq!(e.phase(), Phase::Locked);
    unlock(&mut e, &s, NEW);
    assert_eq!(read(&e, &mut s).unwrap(), b"opaque consumer bundle");
}
#[test]
fn portable_kdf_upgrade_requires_admission_and_rejects_work_tradeoffs() {
    let (baseline, _) = {
        let mut e = Engine::create(OLD, limits()).unwrap();
        e.activate_created().unwrap();
        (e, ())
    };
    let huge = KdfProfile::argon2id(u32::MAX - 3, KdfProfile::baseline().passes()).unwrap();
    // The unapproved cost is rejected before a wrong password could be derived.
    assert!(matches!(
        baseline.draft_kdf_upgrade(b"wrong", huge, [11; 16]),
        Err(Error::Crypto(fogvault::CryptoError::RejectedKdfParameters))
    ));
    assert_eq!(baseline.phase(), Phase::Ready);
    let (mut e, mut s) = create();
    let unchanged = s.clone();
    let draft = e.draft_kdf_upgrade(OLD, target(), [11; 16]).unwrap();
    let p = e.stage_credential_change(&draft).unwrap();
    persist(&mut s, &p);
    e.confirm_credential_commit(&s.descriptor, &s.head).unwrap();
    assert_eq!(e.kdf_profile(), target());
    assert_eq!(s.records, unchanged.records);
    assert_eq!(s.nodes, unchanged.nodes);
    assert!(Engine::open(&s.descriptor, limits()).is_err());
    let mut reopened = Engine::open_with_kdf_policy(&s.descriptor, limits(), policy()).unwrap();
    unlock(&mut reopened, &s, OLD);
    assert_eq!(read(&reopened, &mut s).unwrap(), b"opaque consumer bundle");
    assert!(matches!(
        e.draft_kdf_upgrade(OLD, KdfProfile::baseline(), [12; 16]),
        Err(Error::Crypto(fogvault::CryptoError::RejectedKdfParameters))
    ));
    assert!(e.draft_kdf_upgrade(OLD, target(), [12; 16]).is_err());
    let draft = e.draft_password_change(OLD, NEW, [13; 16]).unwrap();
    let p = e.stage_credential_change(&draft).unwrap();
    persist(&mut s, &p);
    e.confirm_credential_commit(&s.descriptor, &s.head).unwrap();
    assert_eq!(e.kdf_profile(), target());
    assert_eq!(s.records, unchanged.records);
    assert_eq!(s.nodes, unchanged.nodes);
}
#[test]
fn portable_credential_uncertainty_requires_exact_header_and_audit() {
    let (mut e, mut s) = create();
    let old_descriptor = s.descriptor.clone();
    let old_session = e.current_session().unwrap();
    let draft = e.draft_password_change(OLD, NEW, [11; 16]).unwrap();
    let p = e.stage_credential_change(&draft).unwrap();
    persist(&mut s, &p);
    e.mark_unknown().unwrap();
    assert!(matches!(
        e.lookup(&mut s, &ID),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        e.abort_prepared(),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        e.confirm_credential_commit(&s.descriptor, &s.head),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(e
        .begin_reconcile_snapshot(&old_descriptor, &s.head, [11; 16])
        .is_err());
    assert!(e.is_uncertain());
    let mut bad = s.clone();
    bad.records.get_mut(&ID).unwrap().1[0] ^= 1;
    e.begin_reconcile_snapshot(&bad.descriptor, &bad.head, [11; 16])
        .unwrap();
    assert!(audit(&mut e, &bad).is_err());
    e.abort_audit();
    assert!(e.is_uncertain());
    e.begin_reconcile_snapshot(&s.descriptor, &s.head, [11; 16])
        .unwrap();
    audit(&mut e, &s).unwrap();
    assert_eq!(e.descriptor_bytes(), old_descriptor);
    assert_eq!(e.current_session().unwrap(), old_session);
    assert_eq!(e.activate_audit().unwrap(), p.receipt);
    assert!(!e.is_uncertain());
    assert!(matches!(
        e.check_session(&old_session),
        Err(Error::StaleSession)
    ));
    assert_eq!(read(&e, &mut s).unwrap(), b"opaque consumer bundle");
    // The same authorized request remains a zero-rewrap replay even though OLD
    // no longer unlocks the installed descriptor.
    let before = (
        s.descriptor.clone(),
        s.head.clone(),
        e.current_session().unwrap(),
    );
    let retry = e.draft_password_change(OLD, NEW, [11; 16]).unwrap();
    let retry = e.stage_credential_change(&retry).unwrap();
    assert!(retry.replay);
    assert_eq!(retry.receipt, p.receipt);
    assert_eq!(retry.descriptor_bytes, before.0);
    assert_eq!(retry.head_bytes, before.1);
    assert_eq!(e.current_session().unwrap(), before.2);
    assert!(matches!(
        e.draft_password_change(OLD, b"changed content", [11; 16]),
        Err(Error::OperationIdReuse)
    ));
    assert!(matches!(
        e.draft_kdf_upgrade(NEW, target(), [11; 16]),
        Err(Error::OperationIdReuse)
    ));
}
#[test]
fn portable_credential_failures_and_lock_preserve_accepted_policy() {
    let (mut e, mut s) = create();
    let session = e.current_session().unwrap();
    let before = (s.descriptor.clone(), s.head.clone());
    assert!(matches!(
        e.draft_password_change(b"wrong", NEW, [11; 16]),
        Err(Error::Crypto(fogvault::CryptoError::AuthenticationFailed))
    ));
    assert_eq!(e.current_session().unwrap(), session);
    assert_eq!(e.phase(), Phase::Ready);
    assert_eq!(read(&e, &mut s).unwrap(), b"opaque consumer bundle");
    let delayed = e.draft_password_change(OLD, NEW, [11; 16]).unwrap();
    e.lock();
    unlock(&mut e, &s, OLD);
    assert!(matches!(
        e.stage_credential_change(&delayed),
        Err(Error::StaleSession)
    ));
    let draft = e.draft_password_change(OLD, NEW, [12; 16]).unwrap();
    let p = e.stage_credential_change(&draft).unwrap();
    e.abort_prepared().unwrap();
    assert_eq!(e.phase(), Phase::Ready);
    assert!(matches!(
        e.confirm_credential_commit(&p.descriptor_bytes, &p.head_bytes),
        Err(Error::Conflict)
    ));
    assert_eq!(s.descriptor, before.0);
    assert_eq!(s.head, before.1);
    e.lock();
    unlock(&mut e, &s, OLD);
}

#[test]
fn portable_credential_source_observation_does_not_claim_abort_or_corruption() {
    for upgrade in [false, true] {
        let (mut engine, mut store) = create();
        let source = store.clone();
        let request = [91; 16];
        let draft = if upgrade {
            engine.draft_kdf_upgrade(OLD, target(), request)
        } else {
            engine.draft_password_change(OLD, NEW, request)
        }
        .unwrap();
        let plan = engine.stage_credential_change(&draft).unwrap();
        engine.mark_unknown().unwrap();
        assert!(
            matches!(engine.begin_reconcile_snapshot(&source.descriptor,&source.head,request),
            Err(Error::OutcomeUnknown { request_id }) if request_id == request)
        );
        assert!(engine.is_uncertain());
        assert_eq!(engine.pending_request(), Some(request));
        assert_eq!(engine.descriptor_bytes(), source.descriptor);
        assert_eq!(engine.head_bytes(), source.head);
        assert!(matches!(
            engine.abort_prepared(),
            Err(Error::OutcomeUnknown { .. })
        ));
        assert!(matches!(
            read(&engine, &mut store),
            Err(Error::OutcomeUnknown { .. })
        ));
        let mut corrupt_head = source.head.clone();
        corrupt_head[0] ^= 1;
        assert!(engine
            .begin_reconcile_snapshot(&source.descriptor, &corrupt_head, request)
            .is_err());
        assert!(engine.is_uncertain());
        persist(&mut store, &plan);
        engine
            .begin_reconcile_snapshot(&store.descriptor, &store.head, request)
            .unwrap();
        audit(&mut engine, &store).unwrap();
        engine.activate_audit().unwrap();
        assert!(!engine.is_uncertain());
        assert_eq!(
            read(&engine, &mut store).unwrap(),
            b"opaque consumer bundle"
        );
    }
}

#[test]
fn reconcile_unrelated_request_preserves_exact_pending_operation() {
    let (mut engine, mut store) = create();
    let source_descriptor = store.descriptor.clone();
    let source_head = store.head.clone();
    let request = [0xe1; 16];
    let draft = engine.draft_password_change(OLD, NEW, request).unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine.mark_unknown().unwrap();
    for (descriptor, head) in [
        (&source_descriptor, &source_head),
        (&plan.descriptor_bytes, &plan.head_bytes),
    ] {
        assert!(matches!(
            engine.begin_reconcile_snapshot(descriptor, head, [0xe2; 16]),
            Err(Error::Conflict)
        ));
        assert!(engine.is_uncertain());
        assert_eq!(engine.descriptor_bytes(), source_descriptor);
        assert_eq!(engine.head_bytes(), source_head);
    }
    assert!(
        matches!(engine.begin_reconcile_snapshot(&source_descriptor, &source_head, request), Err(Error::OutcomeUnknown {request_id}) if request_id==request)
    );
    persist(&mut store, &plan);
    engine
        .begin_reconcile_snapshot(&store.descriptor, &store.head, request)
        .unwrap();
    audit(&mut engine, &store).unwrap();
    assert_eq!(engine.activate_audit().unwrap(), plan.receipt);
    assert!(!engine.is_uncertain());
    assert_eq!(
        read(&engine, &mut store).unwrap(),
        b"opaque consumer bundle"
    );
}
