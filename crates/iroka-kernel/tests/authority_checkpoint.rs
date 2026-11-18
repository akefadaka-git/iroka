use iroka_kernel::{AuthorityCheckpointStore, SecurityStoreError, SqliteSecurityStore};

#[test]
fn authority_checkpoint_is_monotonic_and_digest_bound() {
    let checkpoint = SqliteSecurityStore::open_in_memory().expect("checkpoint store");
    let first = [0x11_u8; 32];
    let second = [0x22_u8; 32];

    assert_eq!(
        checkpoint.verify_checkpoint("identity_roots", 1, &first),
        Err(SecurityStoreError::Unavailable)
    );
    assert_eq!(
        checkpoint.advance_checkpoint("identity_roots", 1, &first),
        Ok(())
    );
    assert_eq!(
        checkpoint.verify_checkpoint("identity_roots", 1, &first),
        Ok(())
    );
    assert_eq!(
        checkpoint.advance_checkpoint("identity_roots", 1, &second),
        Err(SecurityStoreError::AuthorityCheckpointConflict)
    );
    assert_eq!(
        checkpoint.advance_checkpoint("identity_roots", 2, &second),
        Ok(())
    );
    assert_eq!(
        checkpoint.verify_checkpoint("identity_roots", 1, &first),
        Err(SecurityStoreError::AuthorityCheckpointRollback)
    );
    assert_eq!(
        checkpoint.advance_checkpoint("identity_roots", 1, &first),
        Err(SecurityStoreError::AuthorityCheckpointRollback)
    );
    assert_eq!(
        checkpoint.verify_checkpoint("identity_roots", 2, &second),
        Ok(())
    );
}

#[test]
fn authority_checkpoint_rejects_unknown_registry_and_malformed_digest() {
    let checkpoint = SqliteSecurityStore::open_in_memory().expect("checkpoint store");
    assert_eq!(
        checkpoint.advance_checkpoint("unknown", 1, &[0x33_u8; 32]),
        Err(SecurityStoreError::InvalidVersion)
    );
    assert_eq!(
        checkpoint.advance_checkpoint("identity_succession", 1, &[0x44_u8; 31]),
        Err(SecurityStoreError::InvalidVersion)
    );
}
