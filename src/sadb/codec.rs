//! Tiny length-prefixed byte encoding shared by the `*_db` wrapper modules
//! (`findings_db`, `audit_db`, `calibration_db`, `reasoning_log_db`) that
//! map typed records onto `.sadb` table rows.
//!
//! Deliberately not a general-purpose serialization framework: just the
//! handful of primitives (fixed-width integers, length-prefixed strings,
//! optional strings) those four record shapes actually need.

#[derive(Debug)]
pub struct DecodeError;

impl std::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("malformed .sadb record")
    }
}

impl std::error::Error for DecodeError {}

pub fn write_u8(buffer: &mut Vec<u8>, value: u8) {
    buffer.push(value);
}

pub fn write_bool(buffer: &mut Vec<u8>, value: bool) {
    write_u8(buffer, u8::from(value));
}

pub fn write_u16(buffer: &mut Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

pub fn write_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

pub fn write_u64(buffer: &mut Vec<u8>, value: u64) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

pub fn write_f32(buffer: &mut Vec<u8>, value: f32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

/// Writes `value` as a `u32` length prefix followed by its UTF-8 bytes.
pub fn write_string(buffer: &mut Vec<u8>, value: &str) {
    #[allow(clippy::cast_possible_truncation)]
    write_u32(buffer, value.len() as u32);
    buffer.extend_from_slice(value.as_bytes());
}

pub fn write_option_string(buffer: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(inner) => {
            write_bool(buffer, true);
            write_string(buffer, inner);
        }
        None => write_bool(buffer, false),
    }
}

/// A forward-only cursor over a decoded record's bytes.
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(len).ok_or(DecodeError)?;
        if end > self.bytes.len() {
            return Err(DecodeError);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// # Errors
    ///
    /// Returns [`DecodeError`] if fewer than 1 byte remains.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// # Errors
    ///
    /// Returns [`DecodeError`] if fewer than 1 byte remains.
    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.read_u8()? != 0)
    }

    /// # Errors
    ///
    /// Returns [`DecodeError`] if fewer than 2 bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// # Errors
    ///
    /// Returns [`DecodeError`] if fewer than 4 bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// # Errors
    ///
    /// Returns [`DecodeError`] if fewer than 8 bytes remain.
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().map_err(|_| DecodeError)?,
        ))
    }

    /// # Errors
    ///
    /// Returns [`DecodeError`] if fewer than 4 bytes remain.
    pub fn read_f32(&mut self) -> Result<f32, DecodeError> {
        let bytes = self.take(4)?;
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// # Errors
    ///
    /// Returns [`DecodeError`] if the length prefix names more bytes than
    /// remain, or if those bytes aren't valid UTF-8.
    pub fn read_string(&mut self) -> Result<String, DecodeError> {
        #[allow(clippy::cast_possible_truncation)]
        let len = self.read_u32()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError)
    }

    /// # Errors
    ///
    /// Returns [`DecodeError`] under the same conditions as
    /// [`Self::read_string`], when a string is present.
    pub fn read_option_string(&mut self) -> Result<Option<String>, DecodeError> {
        if self.read_bool()? {
            Ok(Some(self.read_string()?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_primitive() {
        let mut buffer = Vec::new();
        write_u8(&mut buffer, 7);
        write_bool(&mut buffer, true);
        write_u16(&mut buffer, 1_234);
        write_u32(&mut buffer, 123_456);
        write_u64(&mut buffer, 9_876_543_210);
        write_f32(&mut buffer, 3.5);
        write_string(&mut buffer, "hello");

        let mut reader = Reader::new(&buffer);
        assert_eq!(reader.read_u8().unwrap(), 7);
        assert!(reader.read_bool().unwrap());
        assert_eq!(reader.read_u16().unwrap(), 1_234);
        assert_eq!(reader.read_u32().unwrap(), 123_456);
        assert_eq!(reader.read_u64().unwrap(), 9_876_543_210);
        assert!((reader.read_f32().unwrap() - 3.5).abs() < f32::EPSILON);
        assert_eq!(reader.read_string().unwrap(), "hello");
    }

    #[test]
    fn round_trips_present_and_absent_option_strings() {
        let mut buffer = Vec::new();
        write_option_string(&mut buffer, Some("run-1"));
        write_option_string(&mut buffer, None);

        let mut reader = Reader::new(&buffer);
        assert_eq!(
            reader.read_option_string().unwrap(),
            Some("run-1".to_string())
        );
        assert_eq!(reader.read_option_string().unwrap(), None);
    }

    #[test]
    fn reading_past_the_end_is_an_error_not_a_panic() {
        let buffer = vec![1u8, 2];
        let mut reader = Reader::new(&buffer);
        assert!(reader.read_u32().is_err());
    }

    #[test]
    fn a_string_length_pointing_past_the_buffer_is_an_error() {
        let mut buffer = Vec::new();
        write_u32(&mut buffer, 1000);
        buffer.extend_from_slice(b"short");
        let mut reader = Reader::new(&buffer);
        assert!(reader.read_string().is_err());
    }

    #[test]
    fn invalid_utf8_bytes_are_an_error_not_a_panic() {
        let mut buffer = Vec::new();
        write_u32(&mut buffer, 2);
        buffer.extend_from_slice(&[0xFF, 0xFE]);
        let mut reader = Reader::new(&buffer);
        assert!(reader.read_string().is_err());
    }
}
