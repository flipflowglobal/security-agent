//! `security-agent`'s embedded, zero-dependency `.sadb` storage engine.
//!
//! This is a purpose-built append-only store, not a `SQLite` implementation
//! -- see [`pager`] for why. Built bottom-up from [`pager`] (fixed-size
//! pages) and [`heap`] (variable-length records within a page) and
//! [`catalog`] (table name -> tail page), this module adds the last piece:
//! a transaction boundary that makes the whole thing crash-safe.
//!
//! # Why the catalog is immutable too
//!
//! An earlier version of this design treated the catalog page as the one
//! deliberate exception to "never rewrite a page in place." That turned
//! out to be unsafe: if a transaction rewrites the catalog to point at new
//! tail pages and then crashes before it finishes committing, there is no
//! way to undo that rewrite -- the catalog would be left pointing at pages
//! that a crash-recovery truncation is about to discard, a dangling
//! reference with no prior version to restore.
//!
//! So instead, a catalog is never rewritten: each transaction builds a
//! *complete new catalog image* (not a patch) and bump-allocates it as an
//! ordinary immutable page, exactly like a heap page. A small footer page
//! then records which catalog-image page is current. On every [`Database::open`],
//! recovery finds the most recent footer that actually validates (magic
//! bytes plus a checksum), discards every page after it, and loads *that*
//! footer's catalog image. Every page in a `.sadb` file, without
//! exception, is written exactly once and never touched again -- which is
//! exactly what makes a torn write on crash harmless: an incomplete
//! transaction is just a run of orphaned pages with no valid footer
//! pointing at them, discarded wholesale.

pub mod catalog;
pub mod codec;
pub mod heap;
pub mod pager;

use pager::{PAGE_SIZE, Page, Pager, PagerError};
use std::collections::HashMap;
use std::path::Path;

pub use heap::RecordId;

const FIRST_FREE_PAGE: u32 = pager::CATALOG_PAGE + 1;

/// Marks a page as a transaction footer. Distinct from `pager`'s own
/// magic so the two are never confused.
const FOOTER_MAGIC: &[u8; 8] = b"SACOMMT1";
const FOOTER_CATALOG_IMAGE_OFFSET: usize = 8;
const FOOTER_CHECKSUM_OFFSET: usize = 12;

#[derive(Debug)]
pub enum DbError {
    Pager(PagerError),
    Catalog(catalog::CatalogError),
    /// `record` is bigger than a single page can ever hold, even empty.
    RecordTooLarge,
}

impl std::fmt::Display for DbError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pager(source) => write!(formatter, "{source}"),
            Self::Catalog(source) => write!(formatter, "{source}"),
            Self::RecordTooLarge => formatter.write_str("record too large for a single page"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<PagerError> for DbError {
    fn from(source: PagerError) -> Self {
        Self::Pager(source)
    }
}

impl From<catalog::CatalogError> for DbError {
    fn from(source: catalog::CatalogError) -> Self {
        Self::Catalog(source)
    }
}

fn checksum_hex(catalog_image_page: u32) -> String {
    let mut hasher = crate::builtin_tools::Sha256::new();
    hasher.update(FOOTER_MAGIC);
    hasher.update(&catalog_image_page.to_le_bytes());
    hasher.finalize_hex()
}

fn build_footer(catalog_image_page: u32) -> Page {
    let mut page = [0u8; PAGE_SIZE];
    page[0..FOOTER_CATALOG_IMAGE_OFFSET].copy_from_slice(FOOTER_MAGIC);
    page[FOOTER_CATALOG_IMAGE_OFFSET..FOOTER_CHECKSUM_OFFSET]
        .copy_from_slice(&catalog_image_page.to_le_bytes());
    let checksum = checksum_hex(catalog_image_page);
    page[FOOTER_CHECKSUM_OFFSET..FOOTER_CHECKSUM_OFFSET + checksum.len()]
        .copy_from_slice(checksum.as_bytes());
    page
}

/// Returns the footer's `catalog_image_page` if `page` is a valid,
/// untorn footer, or `None` if it's an ordinary data page, an
/// uncommitted footer that never finished writing, or garbage.
fn verify_footer(page: &Page) -> Option<u32> {
    if page[0..FOOTER_CATALOG_IMAGE_OFFSET] != *FOOTER_MAGIC {
        return None;
    }
    let catalog_image_page = u32::from_le_bytes([
        page[FOOTER_CATALOG_IMAGE_OFFSET],
        page[FOOTER_CATALOG_IMAGE_OFFSET + 1],
        page[FOOTER_CATALOG_IMAGE_OFFSET + 2],
        page[FOOTER_CATALOG_IMAGE_OFFSET + 3],
    ]);
    let expected = checksum_hex(catalog_image_page);
    let actual = &page[FOOTER_CHECKSUM_OFFSET..FOOTER_CHECKSUM_OFFSET + expected.len()];
    if actual == expected.as_bytes() {
        Some(catalog_image_page)
    } else {
        None
    }
}

/// Scans backward from end-of-file for the most recent valid, *usable*
/// footer, truncates away everything after it (an interrupted
/// transaction's orphaned pages, if any), and returns the catalog image
/// it names.
///
/// A footer's checksum only proves its own bytes weren't torn -- it
/// doesn't prove `catalog_image_page` is a real, readable page. A
/// legitimately-written footer always names a page strictly before
/// itself (see [`Transaction::commit`]), so a footer naming its own page
/// or later, or a page this pager can't read, is treated exactly like a
/// footer that failed its checksum: skipped, and the scan continues
/// further back for an earlier commit to recover to instead.
///
/// A database that has never had a transaction commit has no footer at
/// all; that's not an error, it just recovers to the pristine empty
/// catalog (page [`pager::CATALOG_PAGE`], all zeros).
fn recover(pager: &mut Pager) -> Result<Page, DbError> {
    let mut page_no = pager.page_count().saturating_sub(1);
    while page_no >= FIRST_FREE_PAGE {
        let page = pager.read_page(page_no)?;
        if let Some(catalog_image_page) = verify_footer(&page) {
            if catalog_image_page < page_no {
                if let Ok(catalog) = pager.read_page(catalog_image_page) {
                    pager.truncate_to(page_no + 1)?;
                    return Ok(catalog);
                }
            }
        }
        page_no -= 1;
    }
    pager.truncate_to(FIRST_FREE_PAGE)?;
    Ok(pager.read_page(pager::CATALOG_PAGE)?)
}

/// A `.sadb` database: a pager plus the catalog image recovered from the
/// most recent valid transaction.
pub struct Database {
    pager: Pager,
    catalog: Page,
}

impl Database {
    /// Opens the database at `path`, creating it if it doesn't exist and
    /// rolling back any transaction that was interrupted mid-commit.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Pager`] for the same reasons
    /// [`pager::Pager::open`] can fail.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let mut pager = Pager::open(path)?;
        let catalog = recover(&mut pager)?;
        Ok(Self { pager, catalog })
    }

    /// Starts a transaction. Nothing this transaction does is visible to
    /// [`Self::scan`] -- or durable across a crash -- until
    /// [`Transaction::commit`] returns.
    pub fn begin(&mut self) -> Transaction<'_> {
        let start_page_count = self.pager.page_count();
        Transaction {
            catalog: self.catalog,
            db: self,
            writers: HashMap::new(),
            start_page_count,
            committed: false,
        }
    }

    /// Reads every committed record in `table`, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Pager`] if a page in the table's chain can't be
    /// read.
    pub fn scan(&mut self, table: &str) -> Result<Vec<Vec<u8>>, DbError> {
        Ok(self
            .scan_with_ids(table)?
            .into_iter()
            .map(|(_id, bytes)| bytes)
            .collect())
    }

    /// Like [`Self::scan`], but pairs each record with the [`RecordId`] it
    /// was inserted at -- for tables another table's rows need to
    /// reference (e.g. `reasoning_thoughts` pointing back at the
    /// `reasoning_runs` row it belongs to).
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Pager`] if a page in the table's chain can't be
    /// read.
    pub fn scan_with_ids(&mut self, table: &str) -> Result<Vec<(RecordId, Vec<u8>)>, DbError> {
        let mut pages = Vec::new();
        let mut page_no = catalog::tail_page(&self.catalog, table).unwrap_or(0);
        while page_no != 0 {
            let page = self.pager.read_page(page_no)?;
            let prev = heap::prev_page(&page);
            pages.push((page_no, page));
            page_no = prev;
        }
        pages.reverse();

        let mut records = Vec::new();
        for (page_no, page) in &pages {
            for slot in 0..heap::record_count(page) {
                if let Some(data) = heap::get(page, slot) {
                    records.push((
                        RecordId {
                            page: *page_no,
                            slot,
                        },
                        data.to_vec(),
                    ));
                }
            }
        }
        Ok(records)
    }
}

struct TableWriter {
    page_no: u32,
    buffer: Page,
}

/// A batch of inserts that either all become visible together (on
/// [`Transaction::commit`]) or -- if dropped uncommitted, or interrupted
/// by a crash -- leave no trace at all.
///
/// Dropping without committing eagerly truncates back to
/// `start_page_count` (see the `Drop` impl below), reclaiming an
/// abandoned transaction's orphaned pages immediately rather than only
/// on the next [`Database::open`]. That's an optimization, not a
/// correctness requirement -- recovery discards the same orphaned pages
/// either way -- so a failed truncate on drop is silently ignored.
pub struct Transaction<'a> {
    db: &'a mut Database,
    catalog: Page,
    writers: HashMap<String, TableWriter>,
    start_page_count: u32,
    committed: bool,
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.db.pager.truncate_to(self.start_page_count);
        }
    }
}

impl Transaction<'_> {
    /// Appends `record` to `table`, returning the [`RecordId`] it can
    /// later be read back at with a direct page read (no scan needed).
    ///
    /// # Errors
    ///
    /// Returns [`DbError::RecordTooLarge`] if `record` cannot fit on a
    /// single page even by itself, or [`DbError::Pager`] if a new page
    /// can't be allocated.
    pub fn insert(&mut self, table: &str, record: &[u8]) -> Result<RecordId, DbError> {
        let writer = match self.writers.entry(table.to_string()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let prev = catalog::tail_page(&self.catalog, table).unwrap_or(0);
                let page_no = self.db.pager.allocate_page()?;
                entry.insert(TableWriter {
                    page_no,
                    buffer: heap::init_page(prev),
                })
            }
        };
        if let Some(slot) = heap::insert(&mut writer.buffer, record) {
            return Ok(RecordId {
                page: writer.page_no,
                slot,
            });
        }

        // This page is full: seal it and start a new one, chained to it.
        self.db.pager.write_page(writer.page_no, &writer.buffer)?;
        catalog::set_tail_page(&mut self.catalog, table, writer.page_no)?;

        let new_page_no = self.db.pager.allocate_page()?;
        let mut new_buffer = heap::init_page(writer.page_no);
        let slot = heap::insert(&mut new_buffer, record).ok_or(DbError::RecordTooLarge)?;
        self.writers.insert(
            table.to_string(),
            TableWriter {
                page_no: new_page_no,
                buffer: new_buffer,
            },
        );
        Ok(RecordId {
            page: new_page_no,
            slot,
        })
    }

    /// Seals every table's in-progress page, writes a new catalog image
    /// and a checksummed footer naming it, and fsyncs -- the point at
    /// which this transaction's inserts become durable and visible to
    /// [`Database::scan`].
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Pager`] if any write or the final sync fails.
    pub fn commit(mut self) -> Result<(), DbError> {
        for (table, writer) in &self.writers {
            self.db.pager.write_page(writer.page_no, &writer.buffer)?;
            catalog::set_tail_page(&mut self.catalog, table, writer.page_no)?;
        }

        let catalog_image_page = self.db.pager.allocate_page()?;
        self.db
            .pager
            .write_page(catalog_image_page, &self.catalog)?;

        let footer_page = self.db.pager.allocate_page()?;
        self.db
            .pager
            .write_page(footer_page, &build_footer(catalog_image_page))?;

        self.db.pager.flush()?;
        self.db.catalog = self.catalog;
        self.committed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "security-agent-sadb-{name}-{}.sadb",
            std::process::id()
        ))
    }

    #[test]
    fn scanning_a_table_that_was_never_created_returns_empty() {
        let path = temp_path("scan-missing-table");
        let _ = fs::remove_file(&path);

        let mut db = Database::open(&path).expect("open");
        let rows = db.scan("findings").expect("scan");
        assert!(rows.is_empty());

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn committed_inserts_are_visible_to_scan_in_insertion_order() {
        let path = temp_path("commit-then-scan");
        let _ = fs::remove_file(&path);

        let mut db = Database::open(&path).expect("open");
        let mut txn = db.begin();
        txn.insert("findings", b"first").expect("insert");
        txn.insert("findings", b"second").expect("insert");
        txn.insert("findings", b"third").expect("insert");
        txn.commit().expect("commit");

        let rows = db.scan("findings").expect("scan");
        assert_eq!(
            rows,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn separate_tables_do_not_interfere_with_each_other() {
        let path = temp_path("separate-tables");
        let _ = fs::remove_file(&path);

        let mut db = Database::open(&path).expect("open");
        let mut txn = db.begin();
        txn.insert("findings", b"a finding").expect("insert");
        txn.insert("audit_records", b"an audit record")
            .expect("insert");
        txn.commit().expect("commit");

        assert_eq!(
            db.scan("findings").expect("scan"),
            vec![b"a finding".to_vec()]
        );
        assert_eq!(
            db.scan("audit_records").expect("scan"),
            vec![b"an audit record".to_vec()]
        );

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn inserts_spanning_multiple_pages_are_all_readable_in_order() {
        let path = temp_path("multi-page-table");
        let _ = fs::remove_file(&path);

        let mut db = Database::open(&path).expect("open");
        let mut txn = db.begin();
        let record = vec![0x42u8; 300];
        let mut expected = Vec::new();
        for _ in 0..40 {
            txn.insert("findings", &record).expect("insert");
            expected.push(record.clone());
        }
        txn.commit().expect("commit");

        let rows = db.scan("findings").expect("scan");
        assert_eq!(rows, expected);

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn a_second_transaction_appends_after_the_first_without_losing_it() {
        let path = temp_path("two-transactions");
        let _ = fs::remove_file(&path);

        let mut db = Database::open(&path).expect("open");
        let mut first = db.begin();
        first.insert("findings", b"one").expect("insert");
        first.commit().expect("commit");

        let mut second = db.begin();
        second.insert("findings", b"two").expect("insert");
        second.commit().expect("commit");

        let rows = db.scan("findings").expect("scan");
        assert_eq!(rows, vec![b"one".to_vec(), b"two".to_vec()]);

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn reopening_after_a_clean_commit_preserves_all_data() {
        let path = temp_path("reopen-after-commit");
        let _ = fs::remove_file(&path);

        {
            let mut db = Database::open(&path).expect("open");
            let mut txn = db.begin();
            txn.insert("findings", b"persisted").expect("insert");
            txn.commit().expect("commit");
        }

        let mut reopened = Database::open(&path).expect("reopen");
        assert_eq!(
            reopened.scan("findings").expect("scan"),
            vec![b"persisted".to_vec()]
        );

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn an_uncommitted_transaction_is_invisible_after_reopening() {
        let path = temp_path("uncommitted-rolls-back");
        let _ = fs::remove_file(&path);

        {
            let mut db = Database::open(&path).expect("open");
            let mut committed = db.begin();
            committed.insert("findings", b"safe").expect("insert");
            committed.commit().expect("commit");

            // Started but never committed -- must not survive a reopen.
            let mut abandoned = db.begin();
            abandoned
                .insert("findings", b"should not persist")
                .expect("insert");
        }

        let mut reopened = Database::open(&path).expect("reopen");
        assert_eq!(
            reopened.scan("findings").expect("scan"),
            vec![b"safe".to_vec()]
        );

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn a_footer_with_a_corrupted_checksum_is_rolled_back_to_the_prior_commit() {
        let path = temp_path("corrupted-footer");
        let _ = fs::remove_file(&path);

        {
            let mut db = Database::open(&path).expect("open");
            let mut first = db.begin();
            first.insert("findings", b"kept").expect("insert");
            first.commit().expect("commit");

            let mut second = db.begin();
            second
                .insert("findings", b"should be discarded")
                .expect("insert");
            second.commit().expect("commit");
        }

        // Corrupt exactly the last page (the second transaction's footer).
        let mut bytes = fs::read(&path).expect("read file");
        let last_page_start = bytes.len() - PAGE_SIZE;
        bytes[last_page_start + FOOTER_CHECKSUM_OFFSET] ^= 0xFF;
        fs::write(&path, bytes).expect("write corrupted file");

        let mut reopened = Database::open(&path).expect("reopen despite corruption");
        assert_eq!(
            reopened.scan("findings").expect("scan"),
            vec![b"kept".to_vec()]
        );

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn dropping_an_uncommitted_transaction_eagerly_truncates_orphaned_pages() {
        let path = temp_path("drop-truncates");
        let _ = fs::remove_file(&path);

        let mut db = Database::open(&path).expect("open");
        let size_before = fs::metadata(&path).expect("stat before").len();
        {
            let mut txn = db.begin();
            txn.insert("findings", &vec![0u8; 2000]).expect("insert");
            // Dropped here without ever calling commit().
        }
        let size_after = fs::metadata(&path).expect("stat after").len();

        fs::remove_file(&path).expect("remove temp file");
        assert_eq!(
            size_after, size_before,
            "an abandoned transaction's pages should be reclaimed immediately on drop, \
             not just on the next reopen"
        );
    }

    #[test]
    fn a_footer_naming_an_unreadable_catalog_page_is_skipped_during_recovery() {
        let path = temp_path("unreadable-catalog-image");
        let _ = fs::remove_file(&path);

        {
            let mut db = Database::open(&path).expect("open");
            let mut txn = db.begin();
            txn.insert("findings", b"kept").expect("insert");
            txn.commit().expect("commit");
        }

        // Append a forged footer: its own checksum is internally valid
        // (computed from the same bogus value it stores), but the
        // catalog_image_page it names is out of range -- simulating a
        // footer whose checksum check alone can't catch a bad reference.
        {
            let mut pager = Pager::open(&path).expect("reopen pager directly");
            let bogus_catalog_image_page = pager.page_count() + 100;
            let footer_page = pager.allocate_page().expect("allocate forged footer page");
            pager
                .write_page(footer_page, &build_footer(bogus_catalog_image_page))
                .expect("write forged footer");
            pager.flush().expect("flush");
        }

        let mut reopened = Database::open(&path).expect("reopen despite the forged footer");
        assert_eq!(
            reopened.scan("findings").expect("scan"),
            vec![b"kept".to_vec()]
        );

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn a_record_larger_than_a_page_is_rejected() {
        let path = temp_path("record-too-large");
        let _ = fs::remove_file(&path);

        let mut db = Database::open(&path).expect("open");
        let mut txn = db.begin();
        let huge = vec![0u8; PAGE_SIZE + 1];
        let result = txn.insert("findings", &huge);

        assert!(matches!(result, Err(DbError::RecordTooLarge)));
        fs::remove_file(&path).expect("remove temp file");
    }
}
