use iroka_kernel::{AuthorityCheckpointStore, SecurityStoreError, SqliteSecurityStore};

#[test]
fn checkpoint_accepts_each_declared_registry_domain() {
    let checkpoint = SqliteSecurityStore::open_in_memory().expect("checkpoint store");
    for (registry, revision) in [
        ("identity_roots", 1),
        ("identity_succession", 2),
        ("compatibility", 3),
    ] {
        checkpoint
            .advance_checkpoint(registry, revision, &[revision as u8; 32])
            .expect("valid registry checkpoint");
        assert_eq!(
            checkpoint.verify_checkpoint(registry, revision, &[revision as u8; 32]),
            Ok(())
        );
    }
    assert_eq!(
        checkpoint.advance_checkpoint("not-a-registry", 1, &[0x77_u8; 32]),
        Err(SecurityStoreError::InvalidVersion)
    );
}
