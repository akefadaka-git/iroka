use iroka_kernel::{AuthorityCheckpointStore, SecurityStoreError, SqliteSecurityStore};

#[test]
fn same_revision_cannot_be_rebound_to_another_digest() {
    let checkpoint = SqliteSecurityStore::open_in_memory().expect("checkpoint store");
    checkpoint
        .advance_checkpoint("compatibility", 4, &[0x10_u8; 32])
        .expect("initial checkpoint");
    assert_eq!(
        checkpoint.advance_checkpoint("compatibility", 4, &[0x20_u8; 32]),
        Err(SecurityStoreError::AuthorityCheckpointConflict)
    );
}
