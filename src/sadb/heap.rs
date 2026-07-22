//! Slot-directory heap pages: variable-length record storage within a
//! single [`Page`](crate::sadb::pager::Page).
//!
//! Layout, matching the classic heap-page shape:
//!
//! ```text
//! ┌ page header (16 bytes) ─────────────────────────────────────────┐
//! │ prev_page: u32 | record_count: u16 | slot_dir_end: u16 |         │
//! │ records_tail: u16 | reserved: 6 bytes                            │
//! ├ slot directory (grows forward, 4 bytes per slot) ────────────────┤
//! │ (offset: u16, length: u16), (offset: u16, length: u16), ...      │
//! ├ free space ───────────────────────────────────────────────────────┤
//! ├ records (grow backward from the end of the page) ─────────────────┤
//! └────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! This module is pure byte manipulation on an in-memory page buffer --
//! no file I/O. Chains of pages link **backward**: each page's
//! `prev_page` names the page that was this table's tail *before* this
//! page was created, and is set once, at that page's creation, and never
//! rewritten. A forward-linking design (an old tail page's `next_page`
//! patched in place once a new page is appended) would mean an
//! already-committed page gets mutated after the fact -- and if a crash
//! then truncates away the new page before its transaction commits, there
//! would be no way to undo that patch, leaving the old page's pointer
//! dangling. Backward links have no such case: a page's header, once
//! written, is never touched again, so truncating away uncommitted pages
//! can never corrupt an earlier, already-committed one.
//!
//! A page is filled by one transaction and then never opened for writing
//! again (see `crate::sadb`'s transaction layer) -- so every byte of a
//! page that's visible on disk was written by exactly one write, never
//! patched, which is what makes a torn write on crash harmless: the whole
//! page is simply discarded if its transaction never committed.

use crate::sadb::pager::{PAGE_SIZE, Page};

const HEADER_SIZE: usize = 16;
const SLOT_SIZE: usize = 4;

/// Identifies one record within a single page: findable directly with
/// [`get`], without a table scan.
///
/// `Hash` makes it usable as a `HashMap` key -- e.g. grouping
/// `reasoning_thoughts` rows by the `reasoning_runs` `RecordId` they
/// reference, without an O(runs × thoughts) scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordId {
    pub page: u32,
    pub slot: u16,
}

const fn read_u32(page: &Page, offset: usize) -> u32 {
    u32::from_le_bytes([
        page[offset],
        page[offset + 1],
        page[offset + 2],
        page[offset + 3],
    ])
}

fn write_u32(page: &mut Page, offset: usize, value: u32) {
    page[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

const fn read_u16(page: &Page, offset: usize) -> u16 {
    u16::from_le_bytes([page[offset], page[offset + 1]])
}

fn write_u16(page: &mut Page, offset: usize, value: u16) {
    page[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// `(prev_page, record_count, slot_dir_end, records_tail)`.
const fn header(page: &Page) -> (u32, u16, u16, u16) {
    (
        read_u32(page, 0),
        read_u16(page, 4),
        read_u16(page, 6),
        read_u16(page, 8),
    )
}

fn write_header(
    page: &mut Page,
    prev_page: u32,
    record_count: u16,
    slot_dir_end: u16,
    records_tail: u16,
) {
    write_u32(page, 0, prev_page);
    write_u16(page, 4, record_count);
    write_u16(page, 6, slot_dir_end);
    write_u16(page, 8, records_tail);
}

fn slot_offset(index: u16) -> usize {
    HEADER_SIZE + usize::from(index) * SLOT_SIZE
}

/// Builds a fresh, empty heap page. `prev_page` is the table's tail page
/// number *before* this page was created (0 if this is the table's first
/// page).
#[must_use]
pub fn init_page(prev_page: u32) -> Page {
    let mut page = [0u8; PAGE_SIZE];
    #[allow(clippy::cast_possible_truncation)]
    write_header(
        &mut page,
        prev_page,
        0,
        HEADER_SIZE as u16,
        PAGE_SIZE as u16,
    );
    page
}

/// The table page that was the tail before this one, or `0` if this page
/// is the first in its table's chain.
#[must_use]
pub const fn prev_page(page: &Page) -> u32 {
    header(page).0
}

/// How many records (including any that may be absent -- this format has
/// no tombstones, so every slot up to this count is live) this page holds.
#[must_use]
pub const fn record_count(page: &Page) -> u16 {
    header(page).1
}

/// Appends `record` to `page`, returning its slot index, or `None` if the
/// page doesn't have room -- the caller should seal this page and start a
/// new one (see `crate::sadb`'s transaction layer).
pub fn insert(page: &mut Page, record: &[u8]) -> Option<u16> {
    let (prev, record_count, slot_dir_end, records_tail) = header(page);
    let required = record.len();
    let slot_dir_end_usize = usize::from(slot_dir_end);
    let records_tail_usize = usize::from(records_tail);
    if slot_dir_end_usize + SLOT_SIZE > records_tail_usize
        || records_tail_usize - slot_dir_end_usize - SLOT_SIZE < required
    {
        return None;
    }

    let new_tail = records_tail_usize - required;
    page[new_tail..new_tail + required].copy_from_slice(record);

    #[allow(clippy::cast_possible_truncation)]
    let new_tail_u16 = new_tail as u16;
    #[allow(clippy::cast_possible_truncation)]
    let required_u16 = required as u16;
    let slot = slot_offset(record_count);
    write_u16(page, slot, new_tail_u16);
    write_u16(page, slot + 2, required_u16);

    let new_count = record_count + 1;
    #[allow(clippy::cast_possible_truncation)]
    let new_slot_dir_end = slot_dir_end + SLOT_SIZE as u16;
    write_header(page, prev, new_count, new_slot_dir_end, new_tail_u16);
    Some(record_count)
}

/// Reads back the record at `slot`, or `None` if `slot` is out of range
/// for this page.
#[must_use]
pub fn get(page: &Page, slot: u16) -> Option<&[u8]> {
    if slot >= record_count(page) {
        return None;
    }
    let offset = slot_offset(slot);
    let record_offset = usize::from(read_u16(page, offset));
    let record_len = usize::from(read_u16(page, offset + 2));
    Some(&page[record_offset..record_offset + record_len])
}

/// Iterates every record on this page, in insertion order.
pub fn iter(page: &Page) -> impl Iterator<Item = &[u8]> {
    (0..record_count(page)).filter_map(move |slot| get(page, slot))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_page_has_no_records_and_the_given_prev_page() {
        let page = init_page(7);
        assert_eq!(prev_page(&page), 7);
        assert_eq!(record_count(&page), 0);
        assert!(iter(&page).next().is_none());
    }

    #[test]
    fn insert_then_get_round_trips_a_record() {
        let mut page = init_page(0);
        let slot = insert(&mut page, b"hello finding").expect("room for one record");
        assert_eq!(slot, 0);
        assert_eq!(get(&page, slot), Some(b"hello finding".as_slice()));
    }

    #[test]
    fn multiple_inserts_are_returned_in_insertion_order_by_iter() {
        let mut page = init_page(0);
        insert(&mut page, b"first").unwrap();
        insert(&mut page, b"second").unwrap();
        insert(&mut page, b"third").unwrap();

        let records: Vec<&[u8]> = iter(&page).collect();
        assert_eq!(records, vec![b"first".as_slice(), b"second", b"third"]);
    }

    #[test]
    fn insert_returns_none_once_the_page_is_full() {
        let mut page = init_page(0);
        let record = vec![0xAB; 200];
        let mut inserted = 0;
        while insert(&mut page, &record).is_some() {
            inserted += 1;
        }
        assert!(inserted > 0);
        assert_eq!(record_count(&page), inserted);
        // Every record that reported success is still readable intact.
        for slot in 0..inserted {
            assert_eq!(get(&page, slot), Some(record.as_slice()));
        }
    }

    #[test]
    fn get_returns_none_for_an_out_of_range_slot() {
        let mut page = init_page(0);
        insert(&mut page, b"only record").unwrap();
        assert_eq!(get(&page, 1), None);
        assert_eq!(get(&page, u16::MAX), None);
    }

    #[test]
    fn an_empty_record_can_still_be_inserted_and_read_back() {
        let mut page = init_page(0);
        let slot = insert(&mut page, b"").expect("room for an empty record");
        assert_eq!(get(&page, slot), Some(b"".as_slice()));
    }
}
