//! The catalog: a page mapping table name -> tail page.
//!
//! A catalog is never rewritten in place -- see `crate::sadb`'s module
//! docs for why. Each transaction instead builds a complete new catalog
//! image (via [`set_tail_page`]) in memory and bump-allocates it as an
//! ordinary immutable page, exactly like a heap page; `crate::sadb`'s
//! transaction footer then records which catalog-image page is current.
//! `crate::sadb::pager::CATALOG_PAGE` (page 1) holds only the pristine,
//! all-zero catalog a brand-new database starts with, before its first
//! transaction ever commits.
//!
//! Like [`crate::sadb::heap`], this module is pure byte manipulation on
//! an in-memory page buffer -- no file I/O. A zeroed page (what
//! `crate::sadb::pager::Pager::open` writes for a brand-new database, and
//! what every catalog image starts from) is already a valid, empty
//! catalog: `table_count` of zero needs no other initialization.

use crate::sadb::pager::{PAGE_SIZE, Page};

/// Table names longer than this don't fit a catalog entry.
pub const MAX_NAME_LEN: usize = 28;
const ENTRY_SIZE: usize = MAX_NAME_LEN + 4;
const HEADER_SIZE: usize = 4;

/// How many tables the catalog page has room for.
pub const MAX_TABLES: usize = (PAGE_SIZE - HEADER_SIZE) / ENTRY_SIZE;

#[derive(Debug)]
pub enum CatalogError {
    /// `table` is longer than [`MAX_NAME_LEN`] bytes.
    NameTooLong(String),
    /// The catalog page already holds [`MAX_TABLES`] tables.
    CatalogFull,
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameTooLong(table) => {
                write!(formatter, "table name too long for the catalog: {table}")
            }
            Self::CatalogFull => formatter.write_str("catalog page has no room for another table"),
        }
    }
}

impl std::error::Error for CatalogError {}

const fn entry_offset(index: usize) -> usize {
    HEADER_SIZE + index * ENTRY_SIZE
}

const fn table_count(page: &Page) -> u16 {
    u16::from_le_bytes([page[0], page[1]])
}

fn set_table_count(page: &mut Page, count: u16) {
    page[0..2].copy_from_slice(&count.to_le_bytes());
}

fn entry_name(page: &Page, index: usize) -> &str {
    let offset = entry_offset(index);
    let raw = &page[offset..offset + MAX_NAME_LEN];
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    std::str::from_utf8(&raw[..end]).unwrap_or("")
}

const fn entry_tail_page(page: &Page, index: usize) -> u32 {
    let offset = entry_offset(index) + MAX_NAME_LEN;
    u32::from_le_bytes([
        page[offset],
        page[offset + 1],
        page[offset + 2],
        page[offset + 3],
    ])
}

fn write_entry(page: &mut Page, index: usize, table: &str, tail_page: u32) {
    let offset = entry_offset(index);
    let name_field = &mut page[offset..offset + MAX_NAME_LEN];
    name_field.fill(0);
    name_field[..table.len()].copy_from_slice(table.as_bytes());
    page[offset + MAX_NAME_LEN..offset + ENTRY_SIZE].copy_from_slice(&tail_page.to_le_bytes());
}

fn find(page: &Page, table: &str) -> Option<usize> {
    (0..usize::from(table_count(page))).find(|&index| entry_name(page, index) == table)
}

/// The tail page currently recorded for `table`, or `None` if the table
/// has no rows yet (or doesn't exist).
#[must_use]
pub fn tail_page(page: &Page, table: &str) -> Option<u32> {
    find(page, table).map(|index| entry_tail_page(page, index))
}

/// Records `tail_page` as the new tail for `table`, creating the entry if
/// this is the table's first row.
///
/// # Errors
///
/// Returns [`CatalogError::NameTooLong`] if `table` doesn't fit in
/// [`MAX_NAME_LEN`] bytes, or [`CatalogError::CatalogFull`] if this would
/// be a new table and the catalog already holds [`MAX_TABLES`].
pub fn set_tail_page(page: &mut Page, table: &str, tail_page: u32) -> Result<(), CatalogError> {
    if table.len() > MAX_NAME_LEN {
        return Err(CatalogError::NameTooLong(table.to_string()));
    }
    if let Some(index) = find(page, table) {
        write_entry(page, index, table, tail_page);
        return Ok(());
    }
    let count = usize::from(table_count(page));
    if count >= MAX_TABLES {
        return Err(CatalogError::CatalogFull);
    }
    write_entry(page, count, table, tail_page);
    #[allow(clippy::cast_possible_truncation)]
    set_table_count(page, count as u16 + 1);
    Ok(())
}

/// Every table name currently in the catalog, in the order they were
/// first created.
pub fn table_names(page: &Page) -> impl Iterator<Item = &str> {
    (0..usize::from(table_count(page))).map(|index| entry_name(page, index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_zeroed_page_is_an_empty_catalog() {
        let page = [0u8; PAGE_SIZE];
        assert_eq!(tail_page(&page, "findings"), None);
        assert_eq!(table_names(&page).count(), 0);
    }

    #[test]
    fn set_then_get_round_trips_a_new_table() {
        let mut page = [0u8; PAGE_SIZE];
        set_tail_page(&mut page, "findings", 5).expect("create table");
        assert_eq!(tail_page(&page, "findings"), Some(5));
        assert_eq!(table_names(&page).collect::<Vec<_>>(), vec!["findings"]);
    }

    #[test]
    fn setting_an_existing_table_updates_its_tail_without_adding_an_entry() {
        let mut page = [0u8; PAGE_SIZE];
        set_tail_page(&mut page, "findings", 5).expect("create table");
        set_tail_page(&mut page, "findings", 9).expect("update table");

        assert_eq!(tail_page(&page, "findings"), Some(9));
        assert_eq!(table_names(&page).count(), 1);
    }

    #[test]
    fn multiple_tables_coexist_independently() {
        let mut page = [0u8; PAGE_SIZE];
        set_tail_page(&mut page, "findings", 5).expect("create findings");
        set_tail_page(&mut page, "audit_records", 8).expect("create audit_records");

        assert_eq!(tail_page(&page, "findings"), Some(5));
        assert_eq!(tail_page(&page, "audit_records"), Some(8));
        assert_eq!(
            table_names(&page).collect::<Vec<_>>(),
            vec!["findings", "audit_records"]
        );
    }

    #[test]
    fn a_name_longer_than_the_limit_is_rejected() {
        let mut page = [0u8; PAGE_SIZE];
        let long_name = "a".repeat(MAX_NAME_LEN + 1);
        let result = set_tail_page(&mut page, &long_name, 1);
        assert!(matches!(result, Err(CatalogError::NameTooLong(_))));
    }

    #[test]
    fn a_name_at_exactly_the_limit_is_accepted() {
        let mut page = [0u8; PAGE_SIZE];
        let exact_name = "a".repeat(MAX_NAME_LEN);
        set_tail_page(&mut page, &exact_name, 3).expect("name at the limit fits");
        assert_eq!(tail_page(&page, &exact_name), Some(3));
    }

    #[test]
    fn the_catalog_rejects_a_new_table_once_full() {
        let mut page = [0u8; PAGE_SIZE];
        for index in 0..MAX_TABLES {
            let name = format!("t{index}");
            set_tail_page(&mut page, &name, 1).expect("room for this table");
        }

        let result = set_tail_page(&mut page, "one_too_many", 1);
        assert!(matches!(result, Err(CatalogError::CatalogFull)));
    }
}
