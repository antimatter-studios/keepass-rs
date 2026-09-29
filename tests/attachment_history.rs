//! Attachments that older versions of an entry still refer to.
#![cfg(feature = "save_kdbx4")]
#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::combo_by_label;
use keepass::db::{fields, Database, EntryId, EntryRef, History, Value};

fn data(entry: &EntryRef<'_>, name: &str) -> Option<Vec<u8>> {
    entry.attachment_by_name(name).map(|a| a.data.get().clone())
}

fn reopen(db: &Database) -> Database {
    let combo = combo_by_label("aes256+none+inner-chacha20+argon2d");
    let bytes = common::save_to_vec(db, combo.get_key());
    Database::open(&mut bytes.as_slice(), combo.get_key()).expect("reopen")
}

/// An entry with `key.bin`, and one older version that has it too.
fn entry_with_history() -> (Database, EntryId) {
    let combo = combo_by_label("aes256+none+inner-chacha20+argon2d");
    let mut db = Database::with_config(combo.get_config());
    let id = {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.add_attachment("key.bin", Value::Unprotected(b"old key".to_vec()));
        e.id()
    };
    db.entry_mut(id)
        .unwrap()
        .edit_tracking(|e| e.set_unprotected(fields::USERNAME, "bob"));
    (db, id)
}

#[test]
fn a_tracked_removal_keeps_the_file_for_the_history() {
    let (mut db, id) = entry_with_history();
    db.entry_mut(id)
        .unwrap()
        .track_changes()
        .as_mut()
        .remove_attachment_by_name("key.bin");

    let entry = db.entry(id).unwrap();
    assert_eq!(data(&entry, "key.bin"), None);
    assert_eq!(
        data(&entry.historical(0).unwrap(), "key.bin"),
        Some(b"old key".to_vec())
    );

    let db = reopen(&db);
    let entry = db.entry(id).unwrap();
    assert_eq!(
        data(&entry.historical(0).unwrap(), "key.bin"),
        Some(b"old key".to_vec())
    );
}

#[test]
fn a_tracked_replacement_keeps_the_old_file_for_the_history() {
    let (mut db, id) = entry_with_history();
    db.entry_mut(id).unwrap().edit_tracking(|e| {
        e.add_attachment("key.bin", Value::Unprotected(b"new key".to_vec()));
    });

    let db = reopen(&db);
    let entry = db.entry(id).unwrap();
    assert_eq!(data(&entry, "key.bin"), Some(b"new key".to_vec()));
    assert_eq!(
        data(&entry.historical(0).unwrap(), "key.bin"),
        Some(b"old key".to_vec())
    );
    assert_eq!(
        data(&entry.historical(1).unwrap(), "key.bin"),
        Some(b"old key".to_vec())
    );
    assert_eq!(db.num_attachments(), 2);
}

/// A file read back shares one attachment between the versions that use the
/// same data, so removing it from one version must leave it for the others.
#[test]
fn removing_a_file_after_reopening_keeps_it_for_the_history() {
    let (db, id) = entry_with_history();
    let mut db = reopen(&db);
    db.entry_mut(id).unwrap().remove_attachment_by_name("key.bin");

    let entry = db.entry(id).unwrap();
    assert_eq!(data(&entry, "key.bin"), None);
    assert_eq!(
        data(&entry.historical(0).unwrap(), "key.bin"),
        Some(b"old key".to_vec())
    );
    assert_eq!(db.num_attachments(), 1);

    let db = reopen(&db);
    let entry = db.entry(id).unwrap();
    assert_eq!(
        data(&entry.historical(0).unwrap(), "key.bin"),
        Some(b"old key".to_vec())
    );
}

#[test]
fn a_file_goes_once_no_version_refers_to_it() {
    let combo = combo_by_label("aes256+none+inner-chacha20+argon2d");
    let mut db = Database::with_config(combo.get_config());
    let (id, other) = {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.add_attachment("key.bin", Value::Unprotected(b"key".to_vec()));
        let id = e.id();
        let mut e = root.add_entry();
        e.add_attachment("other.bin", Value::Unprotected(b"other".to_vec()));
        (id, e.id())
    };
    let mut db = reopen(&db);
    db.entry_mut(id).unwrap().remove_attachment_by_name("key.bin");
    assert_eq!(db.num_attachments(), 1);

    let db = reopen(&db);
    assert_eq!(
        data(&db.entry(other).unwrap(), "other.bin"),
        Some(b"other".to_vec())
    );
}

#[test]
fn removing_the_entry_after_reopening_drops_all_its_files() {
    let (mut db, id) = entry_with_history();
    db.entry_mut(id).unwrap().edit_tracking(|e| {
        e.add_attachment("key.bin", Value::Unprotected(b"new key".to_vec()));
    });
    let mut db = reopen(&db);
    assert_eq!(db.num_attachments(), 2);
    db.entry_mut(id).unwrap().remove();
    assert_eq!(db.num_attachments(), 0);
}

#[test]
fn dropping_a_version_drops_the_files_only_it_used() {
    let (mut db, id) = entry_with_history();
    db.entry_mut(id).unwrap().edit_tracking(|e| {
        e.add_attachment("key.bin", Value::Unprotected(b"new key".to_vec()));
    });
    let mut db = reopen(&db);
    assert_eq!(db.num_attachments(), 2);

    // both versions have the old key: dropping them drops it
    db.entry_mut(id)
        .unwrap()
        .edit_history(|history| *history = History::default());
    assert_eq!(db.num_attachments(), 1);
    let db = reopen(&db);
    let entry = db.entry(id).unwrap();
    assert_eq!(data(&entry, "key.bin"), Some(b"new key".to_vec()));
}
