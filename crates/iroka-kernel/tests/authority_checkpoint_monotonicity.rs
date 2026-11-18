use iroka_kernel::{AuthorityCheckpointStore, SecurityStoreError, SqliteSecurityStore};

#[test]
fn checkpoint_revision_is_monotonic_per_registry() {
    let checkpoint = SqliteSecurityStore::open_in_memory().expect("checkpoint store");
    let digest = [0x66_u8; 32];
    checkpoint
        .advance_checkpoint("compatibility", 2, &digest)
        .expect("first revision");
    assert_eq!(
        checkpoint.advance_checkpoint("compatibility", 1, &digest),
        Err(SecurityStoreError::AuthorityCheckpointRollback)
    );
}
