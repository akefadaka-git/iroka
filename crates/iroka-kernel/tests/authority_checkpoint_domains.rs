use iroka_kernel::{AuthorityCheckpointStore, SecurityStoreError, SqliteSecurityStore};

#[test]
fn registry_checkpoints_are_independent() {
    let checkpoint = SqliteSecurityStore::open_in_memory().expect("checkpoint store");
    let roots_digest = [0x11_u8; 32];
    let succession_digest = [0x22_u8; 32];

    checkpoint
        .advance_checkpoint("identity_roots", 3, &roots_digest)
        .expect("identity-root checkpoint");
    checkpoint
        .advance_checkpoint("identity_succession", 8, &succession_digest)
        .expect("succession checkpoint");

    assert_eq!(
        checkpoint.verify_checkpoint("identity_roots", 3, &roots_digest),
        Ok(())
    );
    assert_eq!(
        checkpoint.verify_checkpoint("identity_succession", 8, &succession_digest),
        Ok(())
    );
    assert_eq!(
        checkpoint.verify_checkpoint("identity_roots", 8, &succession_digest),
        Err(SecurityStoreError::AuthorityCheckpointRollback)
    );
}
