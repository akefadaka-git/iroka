use iroka_kernel::{AuthorityCheckpointStore, SqliteSecurityStore};

#[test]
fn authority_checkpoint_survives_store_restart() {
    let path = std::env::temp_dir().join(format!(
        "iroka-authority-checkpoint-restart-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    let digest = [0x5a_u8; 32];
    let checkpoint = SqliteSecurityStore::open(&path).expect("open checkpoint");
    checkpoint
        .advance_checkpoint("identity_succession", 7, &digest)
        .expect("persist checkpoint");
    drop(checkpoint);

    let reopened = SqliteSecurityStore::open(&path).expect("reopen checkpoint");
    assert_eq!(
        reopened.verify_checkpoint("identity_succession", 7, &digest),
        Ok(())
    );
    drop(reopened);
    let _ = std::fs::remove_file(&path);
}
