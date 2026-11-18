use iroka_kernel::{AuthorityCheckpointStore, SecurityStoreError, SqliteSecurityStore};

#[test]
fn authority_checkpoint_rejects_zero_revision() {
    let checkpoint = SqliteSecurityStore::open_in_memory().expect("checkpoint store");
    assert_eq!(
        checkpoint.advance_checkpoint("identity_roots", 0, &[0x55_u8; 32]),
        Err(SecurityStoreError::InvalidVersion)
    );
}
