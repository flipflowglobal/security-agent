//! Byte-oriented pager for the `.sadb` embedded store.
//!
//! Pages are fixed-size (4096 bytes) and bump-allocated from end-of-file.
//! Once allocated, a page is written once and never rewritten in place --
//! without exception; see `crate::sadb`'s module docs for why even the
//! catalog is bump-allocated fresh on every change rather than patched.
//! The header page is written once, at creation, and never touched again:
//! it carries no counters or state that would otherwise force an in-place
//! rewrite on every allocation.
//!
//! This module is not SQLite-compatible and does not try to be -- it is a
//! purpose-built format for security-agent's own append-only tables
//! (findings, audit records, calibration records, reasoning logs).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Every page in a `.sadb` file, including the header, is exactly this
/// many bytes.
pub const PAGE_SIZE: usize = 4096;

/// Identifies a `.sadb` file and this pager's page size. Chosen to fail
/// loudly (`NotASadbFile`) if pointed at an unrelated file, e.g. a real
/// `SQLite` database -- the two formats are not interchangeable.
const MAGIC: &[u8; 6] = b"SADB1\0";

/// Page 0 is the fixed header. Page 1 is permanently reserved for the
/// catalog. Table data starts at page 2.
const HEADER_PAGE: u32 = 0;
pub const CATALOG_PAGE: u32 = 1;
const FIRST_FREE_PAGE: u32 = 2;

#[derive(Debug)]
pub enum PagerError {
    Io(io::Error),
    /// The file exists but doesn't start with the `.sadb` magic bytes --
    /// most likely a different format entirely (e.g. a real `SQLite` file).
    NotASadbFile,
    /// The header names a page size this build doesn't support.
    UnsupportedPageSize(u32),
    /// The file's length isn't a whole number of pages, or is shorter than
    /// the header + catalog pages it must always have.
    TruncatedFile,
}

impl std::fmt::Display for PagerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "{source}"),
            Self::NotASadbFile => formatter.write_str("not a security-agent database (.sadb) file"),
            Self::UnsupportedPageSize(size) => {
                write!(formatter, "unsupported page size: {size}")
            }
            Self::TruncatedFile => {
                formatter.write_str("database file is shorter than its page grid")
            }
        }
    }
}

impl std::error::Error for PagerError {}

impl From<io::Error> for PagerError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

/// One `PAGE_SIZE`-byte page, read from or about to be written to disk.
pub type Page = [u8; PAGE_SIZE];

/// Opens and grows a single `.sadb` file, one fixed-size page at a time.
///
/// A `Pager` assumes it is the only writer of its file -- true for
/// security-agent's single-process CLI usage -- and never needs to
/// reconcile concurrent writes.
pub struct Pager {
    file: File,
    page_count: u32,
}

impl Pager {
    /// Opens the database at `path`, creating it with a fresh header and
    /// an empty catalog page if it doesn't already exist.
    ///
    /// # Errors
    ///
    /// Returns [`PagerError::NotASadbFile`] if the file exists but wasn't
    /// created by this module, [`PagerError::UnsupportedPageSize`] if it
    /// names a page size this build can't read, [`PagerError::TruncatedFile`]
    /// if its length isn't a whole, complete number of pages, and
    /// [`PagerError::Io`] for the usual filesystem failures.
    pub fn open(path: &Path) -> Result<Self, PagerError> {
        let is_new = !path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        if is_new {
            Self::initialize(&mut file)?;
        }

        let page_count = Self::page_count_from_len(&file)?;
        let mut pager = Self { file, page_count };
        pager.validate_header()?;
        Ok(pager)
    }

    /// Writes the header page and an empty catalog page to a brand-new
    /// file. Never called again for this file -- the header carries no
    /// mutable state.
    fn initialize(file: &mut File) -> Result<(), PagerError> {
        let mut header = [0u8; PAGE_SIZE];
        header[0..6].copy_from_slice(MAGIC);
        #[allow(clippy::cast_possible_truncation)]
        header[6..10].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
        file.write_all(&header)?;
        file.write_all(&[0u8; PAGE_SIZE])?;
        file.sync_all()?;
        Ok(())
    }

    fn page_count_from_len(file: &File) -> Result<u32, PagerError> {
        let length = file.metadata()?.len();
        #[allow(clippy::cast_possible_truncation)]
        let page_size = PAGE_SIZE as u64;
        if length % page_size != 0 {
            return Err(PagerError::TruncatedFile);
        }
        let page_count = length / page_size;
        if page_count > u64::from(u32::MAX) {
            return Err(PagerError::TruncatedFile);
        }
        #[allow(clippy::cast_possible_truncation)]
        Ok(page_count as u32)
    }

    fn validate_header(&mut self) -> Result<(), PagerError> {
        if self.page_count < FIRST_FREE_PAGE {
            return Err(PagerError::TruncatedFile);
        }
        let header = self.read_page(HEADER_PAGE)?;
        if header[0..6] != *MAGIC {
            return Err(PagerError::NotASadbFile);
        }
        let page_size = u32::from_le_bytes([header[6], header[7], header[8], header[9]]);
        #[allow(clippy::cast_possible_truncation)]
        if page_size as usize != PAGE_SIZE {
            return Err(PagerError::UnsupportedPageSize(page_size));
        }
        Ok(())
    }

    /// The number of pages currently allocated, including the header and
    /// catalog pages.
    #[must_use]
    pub const fn page_count(&self) -> u32 {
        self.page_count
    }

    /// Bump-allocates a new, zero-filled page at end-of-file and returns
    /// its page number. Never reuses or rewrites an earlier page.
    ///
    /// # Errors
    ///
    /// Returns [`PagerError::Io`] if the underlying file can't be extended.
    pub fn allocate_page(&mut self) -> Result<u32, PagerError> {
        let page_no = self.page_count;
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&[0u8; PAGE_SIZE])?;
        self.page_count += 1;
        Ok(page_no)
    }

    /// Reads page `page_no` in full.
    ///
    /// # Errors
    ///
    /// Returns [`PagerError::TruncatedFile`] if `page_no` hasn't been
    /// allocated, or [`PagerError::Io`] on a read failure.
    pub fn read_page(&mut self, page_no: u32) -> Result<Page, PagerError> {
        if page_no >= self.page_count {
            return Err(PagerError::TruncatedFile);
        }
        let mut buffer = [0u8; PAGE_SIZE];
        self.file
            .seek(SeekFrom::Start(u64::from(page_no) * PAGE_SIZE as u64))?;
        self.file.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    /// Overwrites `page_no` in place.
    ///
    /// Every caller in this crate writes a given page number exactly once
    /// -- right after allocating it -- and never again; `write_page` itself
    /// doesn't enforce that, it's a property of how `crate::sadb` uses it.
    ///
    /// # Errors
    ///
    /// Returns [`PagerError::TruncatedFile`] if `page_no` hasn't been
    /// allocated, or [`PagerError::Io`] on a write failure.
    pub fn write_page(&mut self, page_no: u32, data: &Page) -> Result<(), PagerError> {
        if page_no >= self.page_count {
            return Err(PagerError::TruncatedFile);
        }
        self.file
            .seek(SeekFrom::Start(u64::from(page_no) * PAGE_SIZE as u64))?;
        self.file.write_all(data)?;
        Ok(())
    }

    /// Flushes and syncs every write made so far to disk.
    ///
    /// # Errors
    ///
    /// Returns [`PagerError::Io`] if the sync fails.
    pub fn flush(&mut self) -> Result<(), PagerError> {
        self.file.flush()?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Resizes the file to exactly `page_count` pages, discarding any
    /// pages beyond it.
    ///
    /// Used only during crash recovery, to discard pages an interrupted
    /// transaction allocated but never got to commit. This never rewrites
    /// the bytes of a page that's kept -- it only ever removes whole pages
    /// from the end.
    ///
    /// # Errors
    ///
    /// Returns [`PagerError::Io`] if the file can't be resized.
    pub fn truncate_to(&mut self, page_count: u32) -> Result<(), PagerError> {
        self.file
            .set_len(u64::from(page_count) * PAGE_SIZE as u64)?;
        self.page_count = page_count;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "security-agent-sadb-pager-{name}-{}.sadb",
            std::process::id()
        ))
    }

    #[test]
    fn opening_a_new_file_reserves_header_and_catalog_pages() {
        let path = temp_path("new-file");
        let _ = fs::remove_file(&path);

        let pager = Pager::open(&path).expect("open should create the file");
        assert_eq!(pager.page_count(), FIRST_FREE_PAGE);

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn allocate_page_grows_the_file_by_one_page_each_time() {
        let path = temp_path("allocate");
        let _ = fs::remove_file(&path);

        let mut pager = Pager::open(&path).expect("open");
        let first = pager.allocate_page().expect("allocate");
        let second = pager.allocate_page().expect("allocate");

        assert_eq!(first, FIRST_FREE_PAGE);
        assert_eq!(second, FIRST_FREE_PAGE + 1);
        assert_eq!(pager.page_count(), FIRST_FREE_PAGE + 2);

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn write_then_read_round_trips_page_contents() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        let mut pager = Pager::open(&path).expect("open");
        let page_no = pager.allocate_page().expect("allocate");

        let mut data = [0u8; PAGE_SIZE];
        data[0] = 0xAB;
        data[PAGE_SIZE - 1] = 0xCD;
        pager.write_page(page_no, &data).expect("write");

        let read_back = pager.read_page(page_no).expect("read");
        assert_eq!(read_back, data);

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn reopening_an_existing_file_preserves_its_pages() {
        let path = temp_path("reopen");
        let _ = fs::remove_file(&path);

        {
            let mut pager = Pager::open(&path).expect("open");
            let page_no = pager.allocate_page().expect("allocate");
            let mut data = [0u8; PAGE_SIZE];
            data[42] = 7;
            pager.write_page(page_no, &data).expect("write");
            pager.flush().expect("flush");
        }

        let mut reopened = Pager::open(&path).expect("reopen");
        assert_eq!(reopened.page_count(), FIRST_FREE_PAGE + 1);
        let read_back = reopened.read_page(FIRST_FREE_PAGE).expect("read");
        assert_eq!(read_back[42], 7);

        fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn opening_a_file_without_the_magic_bytes_is_rejected() {
        let path = temp_path("not-sadb");
        let _ = fs::remove_file(&path);
        fs::write(&path, vec![0u8; PAGE_SIZE * FIRST_FREE_PAGE as usize])
            .expect("write garbage file");

        let result = Pager::open(&path);
        fs::remove_file(&path).expect("remove temp file");
        assert!(matches!(result, Err(PagerError::NotASadbFile)));
    }

    #[test]
    fn opening_a_file_shorter_than_the_reserved_pages_is_rejected() {
        let path = temp_path("too-short");
        let _ = fs::remove_file(&path);
        fs::write(&path, vec![0u8; PAGE_SIZE]).expect("write short file");

        let result = Pager::open(&path);
        fs::remove_file(&path).expect("remove temp file");
        assert!(matches!(result, Err(PagerError::TruncatedFile)));
    }

    #[test]
    fn opening_a_file_with_a_partial_trailing_page_is_rejected() {
        let path = temp_path("partial-tail");
        let _ = fs::remove_file(&path);
        {
            let mut pager = Pager::open(&path).expect("open");
            pager.allocate_page().expect("allocate");
            pager.flush().expect("flush");
        }
        let mut bytes = fs::read(&path).expect("read file");
        bytes.truncate(bytes.len() - 1);
        fs::write(&path, bytes).expect("write truncated file");

        let result = Pager::open(&path);
        fs::remove_file(&path).expect("remove temp file");
        assert!(matches!(result, Err(PagerError::TruncatedFile)));
    }

    #[test]
    fn reading_an_unallocated_page_is_rejected() {
        let path = temp_path("unallocated");
        let _ = fs::remove_file(&path);

        let mut pager = Pager::open(&path).expect("open");
        let result = pager.read_page(pager.page_count());

        fs::remove_file(&path).expect("remove temp file");
        assert!(matches!(result, Err(PagerError::TruncatedFile)));
    }
}
