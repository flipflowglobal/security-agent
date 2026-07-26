use crate::builtin_tools::{BuiltInToolError, sha256_file};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const MAX_PACKETS: u64 = 1_000_000;
const MAX_CAPTURED_PACKET_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolCounts {
    pub ethernet: u64,
    pub vlan: u64,
    pub ipv4: u64,
    pub ipv6: u64,
    pub arp: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub icmpv6: u64,
    pub other_network: u64,
    pub malformed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureTimestamp {
    pub seconds: u32,
    pub nanoseconds: u32,
}

impl fmt::Display for CaptureTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{:09}", self.seconds, self.nanoseconds)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WiresharkReport {
    pub capture: PathBuf,
    pub sha256: String,
    pub format: &'static str,
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub link_type: u32,
    pub packets: u64,
    pub captured_bytes: u64,
    pub original_bytes: u64,
    pub truncated_packets: u64,
    pub first_timestamp: Option<CaptureTimestamp>,
    pub last_timestamp: Option<CaptureTimestamp>,
    pub protocols: ProtocolCounts,
}

impl fmt::Display for WiresharkReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Wireshark Local Capture Report")?;
        writeln!(formatter, "==============================")?;
        writeln!(formatter, "Implementation : Built-in substitute")?;
        writeln!(formatter, "Network used   : No")?;
        writeln!(formatter, "Capture file   : {}", self.capture.display())?;
        writeln!(formatter, "SHA-256        : {}", self.sha256)?;
        writeln!(formatter)?;
        writeln!(formatter, "Capture Summary")?;
        writeln!(formatter, "---------------")?;
        writeln!(formatter, "Format         : {}", self.format)?;
        writeln!(
            formatter,
            "Version        : {}.{}",
            self.version_major, self.version_minor
        )?;
        writeln!(formatter, "Snapshot length: {} bytes", self.snaplen)?;
        writeln!(formatter, "Link type      : {}", self.link_type)?;
        writeln!(formatter, "Packets        : {}", self.packets)?;
        writeln!(formatter, "Captured bytes : {}", self.captured_bytes)?;
        writeln!(formatter, "Original bytes : {}", self.original_bytes)?;
        writeln!(formatter, "Truncated      : {}", self.truncated_packets)?;
        writeln!(
            formatter,
            "First timestamp: {}",
            optional_timestamp(self.first_timestamp.as_ref())
        )?;
        writeln!(
            formatter,
            "Last timestamp : {}",
            optional_timestamp(self.last_timestamp.as_ref())
        )?;
        writeln!(formatter)?;
        writeln!(formatter, "Protocol Counts")?;
        writeln!(formatter, "---------------")?;
        writeln!(formatter, "Ethernet       : {}", self.protocols.ethernet)?;
        writeln!(formatter, "VLAN           : {}", self.protocols.vlan)?;
        writeln!(formatter, "IPv4           : {}", self.protocols.ipv4)?;
        writeln!(formatter, "IPv6           : {}", self.protocols.ipv6)?;
        writeln!(formatter, "ARP            : {}", self.protocols.arp)?;
        writeln!(formatter, "TCP            : {}", self.protocols.tcp)?;
        writeln!(formatter, "UDP            : {}", self.protocols.udp)?;
        writeln!(formatter, "ICMP           : {}", self.protocols.icmp)?;
        writeln!(formatter, "ICMPv6         : {}", self.protocols.icmpv6)?;
        writeln!(
            formatter,
            "Other network  : {}",
            self.protocols.other_network
        )?;
        writeln!(formatter, "Malformed      : {}", self.protocols.malformed)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

struct GlobalHeader {
    order: ByteOrder,
    nanosecond_resolution: bool,
    format: &'static str,
    version_major: u16,
    version_minor: u16,
    snaplen: u32,
    link_type: u32,
}

fn read_global_header(file: &mut File, capture: &Path) -> Result<GlobalHeader, BuiltInToolError> {
    let mut global = [0_u8; 24];
    read_exact_capture(file, &mut global, capture, "truncated PCAP global header")?;
    let (order, nanosecond_resolution, format) =
        parse_magic([global[0], global[1], global[2], global[3]])?;
    let version_major = read_u16(&global[4..6], order);
    let version_minor = read_u16(&global[6..8], order);
    if version_major != 2 || version_minor != 4 {
        return Err(BuiltInToolError::InvalidInput(format!(
            "unsupported PCAP version {version_major}.{version_minor}"
        )));
    }
    let snaplen = read_u32(&global[16..20], order);
    if snaplen == 0 {
        return Err(BuiltInToolError::InvalidInput(
            "PCAP snapshot length must be greater than zero".to_string(),
        ));
    }
    let link_type = read_u32(&global[20..24], order);
    Ok(GlobalHeader {
        order,
        nanosecond_resolution,
        format,
        version_major,
        version_minor,
        snaplen,
        link_type,
    })
}

struct PacketRecord {
    timestamp: CaptureTimestamp,
    captured_length: u32,
    original_length: u32,
    data: Vec<u8>,
}

/// Reads the next packet record, or `Ok(None)` at a clean end of capture.
fn read_packet_record(
    file: &mut File,
    capture: &Path,
    header: &GlobalHeader,
    packets_so_far: u64,
) -> Result<Option<PacketRecord>, BuiltInToolError> {
    let mut packet_header = [0_u8; 16];
    let first_byte = read_capture(file, &mut packet_header[..1], capture)?;
    if first_byte == 0 {
        return Ok(None);
    }
    read_exact_capture(
        file,
        &mut packet_header[1..],
        capture,
        "truncated PCAP packet header",
    )?;
    if packets_so_far >= MAX_PACKETS {
        return Err(BuiltInToolError::InvalidInput(format!(
            "PCAP packet limit exceeded: {MAX_PACKETS}"
        )));
    }
    let packet_number = packets_so_far + 1;

    let seconds = read_u32(&packet_header[0..4], header.order);
    let fraction = read_u32(&packet_header[4..8], header.order);
    let captured_length = read_u32(&packet_header[8..12], header.order);
    let original_length = read_u32(&packet_header[12..16], header.order);
    if captured_length > header.snaplen {
        return Err(BuiltInToolError::InvalidInput(format!(
            "packet {packet_number} captured length {captured_length} exceeds snapshot length {}",
            header.snaplen
        )));
    }
    if captured_length > original_length {
        return Err(BuiltInToolError::InvalidInput(format!(
            "packet {packet_number} captured length {captured_length} exceeds original length {original_length}"
        )));
    }
    let captured_length_usize = captured_length as usize;
    if captured_length_usize > MAX_CAPTURED_PACKET_BYTES {
        return Err(BuiltInToolError::InvalidInput(format!(
            "packet {packet_number} exceeds local packet-size limit"
        )));
    }
    let nanoseconds = if header.nanosecond_resolution {
        fraction
    } else {
        fraction.checked_mul(1_000).ok_or_else(|| {
            BuiltInToolError::InvalidInput("invalid PCAP microsecond timestamp".to_string())
        })?
    };
    if nanoseconds >= 1_000_000_000 {
        return Err(BuiltInToolError::InvalidInput(format!(
            "packet {packet_number} has invalid fractional timestamp"
        )));
    }

    let mut data = vec![0_u8; captured_length_usize];
    read_exact_capture(file, &mut data, capture, "truncated PCAP packet data")?;

    Ok(Some(PacketRecord {
        timestamp: CaptureTimestamp {
            seconds,
            nanoseconds,
        },
        captured_length,
        original_length,
        data,
    }))
}

/// Parses the classic PCAP file at `input` into a [`WiresharkReport`].
///
/// # Errors
///
/// Returns [`BuiltInToolError::InvalidInput`] if `input` is a symbolic link,
/// not a regular file, not classic PCAP, uses an unsupported version, or
/// contains a malformed/oversized/truncated packet; and
/// [`BuiltInToolError::Io`] on any filesystem failure.
pub fn run_wireshark(input: &Path) -> Result<WiresharkReport, BuiltInToolError> {
    let input_metadata = fs::symlink_metadata(input).map_err(|source| BuiltInToolError::Io {
        path: input.to_path_buf(),
        source,
    })?;
    if input_metadata.file_type().is_symlink() {
        return Err(BuiltInToolError::InvalidInput(
            "capture file must not be a symbolic link".to_string(),
        ));
    }
    if !input_metadata.is_file() {
        return Err(BuiltInToolError::InvalidInput(
            "capture input must be a regular PCAP file".to_string(),
        ));
    }

    let capture = input
        .canonicalize()
        .map_err(|source| BuiltInToolError::Io {
            path: input.to_path_buf(),
            source,
        })?;
    let mut file = File::open(&capture).map_err(|source| BuiltInToolError::Io {
        path: capture.clone(),
        source,
    })?;
    let header = read_global_header(&mut file, &capture)?;

    let mut report = WiresharkReport {
        capture: capture.clone(),
        sha256: String::new(),
        format: header.format,
        version_major: header.version_major,
        version_minor: header.version_minor,
        snaplen: header.snaplen,
        link_type: header.link_type,
        packets: 0,
        captured_bytes: 0,
        original_bytes: 0,
        truncated_packets: 0,
        first_timestamp: None,
        last_timestamp: None,
        protocols: ProtocolCounts::default(),
    };

    while let Some(packet) = read_packet_record(&mut file, &capture, &header, report.packets)? {
        if report.first_timestamp.is_none() {
            report.first_timestamp = Some(packet.timestamp.clone());
        }
        report.last_timestamp = Some(packet.timestamp);
        report.packets += 1;
        report.captured_bytes = report
            .captured_bytes
            .checked_add(u64::from(packet.captured_length))
            .ok_or(BuiltInToolError::SizeOverflow)?;
        report.original_bytes = report
            .original_bytes
            .checked_add(u64::from(packet.original_length))
            .ok_or(BuiltInToolError::SizeOverflow)?;
        if packet.captured_length < packet.original_length {
            report.truncated_packets += 1;
        }
        classify_packet(header.link_type, &packet.data, &mut report.protocols);
    }

    report.sha256 = sha256_file(&capture)?;
    Ok(report)
}

fn parse_magic(magic: [u8; 4]) -> Result<(ByteOrder, bool, &'static str), BuiltInToolError> {
    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => Ok((ByteOrder::Little, false, "PCAP microsecond")),
        [0xa1, 0xb2, 0xc3, 0xd4] => Ok((ByteOrder::Big, false, "PCAP microsecond")),
        [0x4d, 0x3c, 0xb2, 0xa1] => Ok((ByteOrder::Little, true, "PCAP nanosecond")),
        [0xa1, 0xb2, 0x3c, 0x4d] => Ok((ByteOrder::Big, true, "PCAP nanosecond")),
        _ => Err(BuiltInToolError::InvalidInput(
            "unsupported capture format; classic PCAP is required".to_string(),
        )),
    }
}

fn classify_packet(link_type: u32, packet: &[u8], counts: &mut ProtocolCounts) {
    if link_type != 1 {
        counts.other_network += 1;
        return;
    }
    counts.ethernet += 1;
    if packet.len() < 14 {
        counts.malformed += 1;
        return;
    }
    let mut ether_type = u16::from_be_bytes([packet[12], packet[13]]);
    let mut network_offset = 14;
    while matches!(ether_type, 0x8100 | 0x88a8) {
        counts.vlan += 1;
        if packet.len() < network_offset + 4 {
            counts.malformed += 1;
            return;
        }
        ether_type = u16::from_be_bytes([packet[network_offset + 2], packet[network_offset + 3]]);
        network_offset += 4;
    }
    match ether_type {
        0x0800 => classify_ipv4(packet, network_offset, counts),
        0x86dd => classify_ipv6(packet, network_offset, counts),
        0x0806 => counts.arp += 1,
        _ => counts.other_network += 1,
    }
}

fn classify_ipv4(packet: &[u8], offset: usize, counts: &mut ProtocolCounts) {
    counts.ipv4 += 1;
    if packet.len() < offset + 20 || packet[offset] >> 4 != 4 {
        counts.malformed += 1;
        return;
    }
    let header_length = usize::from(packet[offset] & 0x0f) * 4;
    if header_length < 20 || packet.len() < offset + header_length {
        counts.malformed += 1;
        return;
    }
    classify_transport(packet[offset + 9], counts);
}

fn classify_ipv6(packet: &[u8], offset: usize, counts: &mut ProtocolCounts) {
    counts.ipv6 += 1;
    if packet.len() < offset + 40 || packet[offset] >> 4 != 6 {
        counts.malformed += 1;
        return;
    }
    classify_transport(packet[offset + 6], counts);
}

const fn classify_transport(protocol: u8, counts: &mut ProtocolCounts) {
    match protocol {
        1 => counts.icmp += 1,
        6 => counts.tcp += 1,
        17 => counts.udp += 1,
        58 => counts.icmpv6 += 1,
        _ => counts.other_network += 1,
    }
}

fn read_u16(bytes: &[u8], order: ByteOrder) -> u16 {
    let value = [bytes[0], bytes[1]];
    match order {
        ByteOrder::Little => u16::from_le_bytes(value),
        ByteOrder::Big => u16::from_be_bytes(value),
    }
}

fn read_u32(bytes: &[u8], order: ByteOrder) -> u32 {
    let value = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match order {
        ByteOrder::Little => u32::from_le_bytes(value),
        ByteOrder::Big => u32::from_be_bytes(value),
    }
}

fn read_capture(
    file: &mut File,
    buffer: &mut [u8],
    path: &Path,
) -> Result<usize, BuiltInToolError> {
    file.read(buffer).map_err(|source| BuiltInToolError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_exact_capture(
    file: &mut File,
    buffer: &mut [u8],
    path: &Path,
    truncated_message: &str,
) -> Result<(), BuiltInToolError> {
    file.read_exact(buffer).map_err(|source| {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            BuiltInToolError::InvalidInput(truncated_message.to_string())
        } else {
            BuiltInToolError::Io {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn optional_timestamp(timestamp: Option<&CaptureTimestamp>) -> String {
    timestamp.map_or_else(|| "not present".to_string(), ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn wireshark_parses_ethernet_ipv4_udp_capture() {
        let report = analyze_capture("udp", &valid_udp_capture()).expect("analyze capture");

        assert_eq!(report.packets, 1);
        assert_eq!(report.protocols.ethernet, 1);
        assert_eq!(report.protocols.ipv4, 1);
        assert_eq!(report.protocols.udp, 1);
        assert_eq!(report.protocols.malformed, 0);
        assert_eq!(report.captured_bytes, 42);
        assert_eq!(
            report.first_timestamp,
            Some(CaptureTimestamp {
                seconds: 1,
                nanoseconds: 500_000_000
            })
        );
    }

    #[test]
    fn wireshark_parses_big_endian_nanosecond_capture() {
        let report = analyze_capture("big-nano", &valid_big_endian_nanosecond_capture())
            .expect("analyze big-endian capture");

        assert_eq!(report.format, "PCAP nanosecond");
        assert_eq!(report.packets, 1);
        assert_eq!(
            report.first_timestamp,
            Some(CaptureTimestamp {
                seconds: 2,
                nanoseconds: 123_456_789
            })
        );
    }

    #[test]
    fn wireshark_classifies_stacked_vlan_ipv6_tcp() {
        let mut packet = vec![0_u8; 12];
        packet.extend_from_slice(&0x88a8_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0x8100_u16.to_be_bytes());
        packet.extend_from_slice(&2_u16.to_be_bytes());
        packet.extend_from_slice(&0x86dd_u16.to_be_bytes());
        let mut ipv6 = [0_u8; 40];
        ipv6[0] = 0x60;
        ipv6[6] = 6;
        packet.extend_from_slice(&ipv6);
        let mut counts = ProtocolCounts::default();

        classify_packet(1, &packet, &mut counts);

        assert_eq!(counts.ethernet, 1);
        assert_eq!(counts.vlan, 2);
        assert_eq!(counts.ipv6, 1);
        assert_eq!(counts.tcp, 1);
        assert_eq!(counts.malformed, 0);
    }

    #[test]
    fn wireshark_rejects_captured_length_above_original() {
        let mut capture = valid_udp_capture();
        capture[32..36].copy_from_slice(&43_u32.to_le_bytes());

        let result = analyze_capture("invalid-length", &capture);

        assert!(matches!(result, Err(BuiltInToolError::InvalidInput(_))));
    }

    #[test]
    fn wireshark_rejects_truncated_packet_header() {
        let mut capture = valid_udp_capture();
        capture.truncate(25);

        let result = analyze_capture("truncated", &capture);

        assert!(matches!(result, Err(BuiltInToolError::InvalidInput(_))));
    }

    fn analyze_capture(name: &str, contents: &[u8]) -> Result<WiresharkReport, BuiltInToolError> {
        let path = std::env::temp_dir().join(format!(
            "security-agent-wireshark-{name}-{}.pcap",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let mut capture = File::create(&path).expect("create capture");
        capture.write_all(contents).expect("write capture");
        drop(capture);
        let result = run_wireshark(&path);
        fs::remove_file(path).expect("remove capture");
        result
    }

    fn valid_udp_capture() -> Vec<u8> {
        let mut capture = Vec::new();
        capture.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        capture.extend_from_slice(&2_u16.to_le_bytes());
        capture.extend_from_slice(&4_u16.to_le_bytes());
        capture.extend_from_slice(&0_i32.to_le_bytes());
        capture.extend_from_slice(&0_u32.to_le_bytes());
        capture.extend_from_slice(&65_535_u32.to_le_bytes());
        capture.extend_from_slice(&1_u32.to_le_bytes());
        capture.extend_from_slice(&1_u32.to_le_bytes());
        capture.extend_from_slice(&500_000_u32.to_le_bytes());
        capture.extend_from_slice(&42_u32.to_le_bytes());
        capture.extend_from_slice(&42_u32.to_le_bytes());
        capture.extend_from_slice(&[0; 12]);
        capture.extend_from_slice(&0x0800_u16.to_be_bytes());
        capture.extend_from_slice(&[
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        ]);
        capture.extend_from_slice(&[0, 53, 0, 53, 0, 8, 0, 0]);
        capture
    }

    fn valid_big_endian_nanosecond_capture() -> Vec<u8> {
        let base_capture = valid_udp_capture();
        let frame = &base_capture[40..];
        let mut capture = Vec::new();
        capture.extend_from_slice(&[0xa1, 0xb2, 0x3c, 0x4d]);
        capture.extend_from_slice(&2_u16.to_be_bytes());
        capture.extend_from_slice(&4_u16.to_be_bytes());
        capture.extend_from_slice(&0_i32.to_be_bytes());
        capture.extend_from_slice(&0_u32.to_be_bytes());
        capture.extend_from_slice(&65_535_u32.to_be_bytes());
        capture.extend_from_slice(&1_u32.to_be_bytes());
        capture.extend_from_slice(&2_u32.to_be_bytes());
        capture.extend_from_slice(&123_456_789_u32.to_be_bytes());
        capture.extend_from_slice(&42_u32.to_be_bytes());
        capture.extend_from_slice(&42_u32.to_be_bytes());
        capture.extend_from_slice(frame);
        capture
    }
}
