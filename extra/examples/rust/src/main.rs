//! read_flows — usage example for the nfdump read ABI from Rust.
//!
//! Hand-declares the extern "C" surface of
//! ../../../src/libnffile/nfdump.h rather than pulling in bindgen (see
//! Cargo.toml) - fine for a small, stable header like this one.
//!
//! Note the deliberate choice below to represent nfdump_status_t and
//! nfdump_field_id_t as plain i32 constants, not Rust `enum`s: an enum
//! crossing an FFI boundary must never hold a discriminant Rust doesn't
//! know about, which a C function returning an int makes easy to violate
//! by accident. Plain constants compared against a plain i32 avoid that
//! footgun entirely - see nfdump.h's own "no exceptions, no UB" framing.

use std::ffi::{c_char, c_void, CString};
use std::net::Ipv6Addr;
use std::ptr;

// ---------------------------------------------------------------------
// nfdump_status_t
// ---------------------------------------------------------------------
const STATUS_OK: i32 = 0;
const STATUS_EOF: i32 = 1;
#[allow(dead_code)] // part of the full status mirror; the getters below only distinguish OK vs. not-OK
const STATUS_ABSENT: i32 = 2;

// ---------------------------------------------------------------------
// nfdump_field_id_t - must match nfdump.h exactly: same order, same
// values (1-based, append-only). Never renumber.
// ---------------------------------------------------------------------
#[allow(dead_code)]
mod field {
    pub const FIRST_SEEN: i32 = 1;
    pub const LAST_SEEN: i32 = 2;
    pub const RECEIVED: i32 = 3;
    pub const IP_VERSION: i32 = 4;
    pub const SRC_ADDR: i32 = 5;
    pub const DST_ADDR: i32 = 6;
    pub const SRC_PORT: i32 = 7;
    pub const DST_PORT: i32 = 8;
    pub const ICMP_TYPE: i32 = 9;
    pub const ICMP_CODE: i32 = 10;
    pub const PROTO: i32 = 11;
    pub const TCP_FLAGS: i32 = 12;
    pub const SRC_TOS: i32 = 13;
    pub const FWD_STATUS: i32 = 14;
    pub const IN_PACKETS: i32 = 15;
    pub const IN_BYTES: i32 = 16;
    pub const OUT_PACKETS: i32 = 17;
    pub const OUT_BYTES: i32 = 18;
    pub const AGGR_FLOWS: i32 = 19;
    pub const INPUT_IF: i32 = 20;
    pub const OUTPUT_IF: i32 = 21;
    pub const SRC_AS: i32 = 22;
    pub const DST_AS: i32 = 23;
    pub const SRC_VLAN: i32 = 24;
    pub const DST_VLAN: i32 = 25;
    pub const SRC_MASK: i32 = 26;
    pub const DST_MASK: i32 = 27;
    pub const DIRECTION: i32 = 28;
    pub const DST_TOS: i32 = 29;
    pub const FLOW_END_REASON: i32 = 30;
    pub const EXPORTER_ID: i32 = 31;
    pub const ENGINE_TYPE: i32 = 32;
    pub const ENGINE_ID: i32 = 33;
    pub const NF_VERSION: i32 = 34;
}

const ABI_VERSION: u32 = 1;

// ---------------------------------------------------------------------
// struct mirrors - #[repr(C)] gives the same layout/padding rules as a C
// compiler, so field order/types matching nfdump.h is all that's needed.
// ---------------------------------------------------------------------
#[repr(C)]
struct NfdumpReader {
    _private: [u8; 0],
} // opaque

#[repr(C)]
struct ReaderOptions {
    abi_version: u32,
    struct_size: u32,
    passphrase: *const c_char,
}

#[repr(C)]
struct RecordView {
    abi_version: u32,
    struct_size: u32,
    ordinal: u64,
    data: *const u8,
    size: u32,
}

#[repr(C)]
struct FileInfo {
    abi_version: u32,
    struct_size: u32,
    num_flows: u64,
    num_bytes: u64,
    num_packets: u64,
    msec_first_seen: u64,
    msec_last_seen: u64,
    ident: *const c_char,
}

#[repr(C)]
struct FieldInfo {
    abi_version: u32,
    struct_size: u32,
    name: *const c_char,
    field_type: i32,
    size: u16,
}

extern "C" {
    fn nfdump_abi_version() -> u32;
    fn nfdump_reader_open(path: *const c_char, options: *const ReaderOptions, out_reader: *mut *mut NfdumpReader) -> i32;
    fn nfdump_reader_close(reader: *mut NfdumpReader);
    fn nfdump_reader_last_error(reader: *const NfdumpReader) -> *const c_char;
    fn nfdump_reader_next(reader: *mut NfdumpReader, record: *mut RecordView) -> i32;
    fn nfdump_reader_file_info(reader: *const NfdumpReader, out: *mut FileInfo) -> i32;
    fn nfdump_field_count() -> usize;
    fn nfdump_field_describe(field: i32, out: *mut FieldInfo) -> i32;
    fn nfdump_record_get(reader: *mut NfdumpReader, field: i32, out: *mut c_void, out_size: usize) -> i32;
}

/// Safe wrapper: owns the reader handle, closes it on Drop.
struct Reader {
    ptr: *mut NfdumpReader,
}

impl Reader {
    fn open(path: &str) -> Result<Reader, i32> {
        let cpath = CString::new(path).expect("path has no embedded NUL");
        let mut ptr: *mut NfdumpReader = ptr::null_mut();
        // fails closed: on any error nfdump_reader_open() leaves ptr NULL -
        // see nfdump.h - so there is nothing to clean up here on the Err path.
        let st = unsafe { nfdump_reader_open(cpath.as_ptr(), ptr::null(), &mut ptr) };
        if st != STATUS_OK {
            return Err(st);
        }
        Ok(Reader { ptr })
    }

    fn file_info(&self) -> Result<FileInfo, i32> {
        let mut info = FileInfo {
            abi_version: ABI_VERSION,
            struct_size: std::mem::size_of::<FileInfo>() as u32,
            num_flows: 0,
            num_bytes: 0,
            num_packets: 0,
            msec_first_seen: 0,
            msec_last_seen: 0,
            ident: ptr::null(),
        };
        let st = unsafe { nfdump_reader_file_info(self.ptr, &mut info) };
        if st != STATUS_OK {
            return Err(st);
        }
        Ok(info)
    }

    /// Advances to the next record. Ok(None) at EOF, matching
    /// nfdump_reader_next()'s NFDUMP_EOF.
    fn next_record(&mut self) -> Result<Option<RecordView>, i32> {
        let mut rec = RecordView { abi_version: 0, struct_size: 0, ordinal: 0, data: ptr::null(), size: 0 };
        let st = unsafe { nfdump_reader_next(self.ptr, &mut rec) };
        match st {
            STATUS_OK => Ok(Some(rec)),
            STATUS_EOF => Ok(None),
            _ => Err(st),
        }
    }

    fn get_u64(&self, field: i32) -> Option<u64> {
        let mut v: u64 = 0;
        let st = unsafe { nfdump_record_get(self.ptr, field, &mut v as *mut u64 as *mut c_void, 8) };
        (st == STATUS_OK).then_some(v)
    }

    fn get_u16(&self, field: i32) -> Option<u16> {
        let mut v: u16 = 0;
        let st = unsafe { nfdump_record_get(self.ptr, field, &mut v as *mut u16 as *mut c_void, 2) };
        (st == STATUS_OK).then_some(v)
    }

    fn get_u8(&self, field: i32) -> Option<u8> {
        let mut v: u8 = 0;
        let st = unsafe { nfdump_record_get(self.ptr, field, &mut v as *mut u8 as *mut c_void, 1) };
        (st == STATUS_OK).then_some(v)
    }

    fn get_addr(&self, field: i32) -> Option<std::net::IpAddr> {
        let mut buf = [0u8; 16];
        let st = unsafe { nfdump_record_get(self.ptr, field, buf.as_mut_ptr() as *mut c_void, 16) };
        if st != STATUS_OK {
            return None;
        }
        let v6 = Ipv6Addr::from(buf);
        Some(v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(std::net::IpAddr::V6(v6)))
    }

    fn last_error(&self) -> String {
        unsafe {
            let s = nfdump_reader_last_error(self.ptr);
            if s.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(s).to_string_lossy().into_owned()
            }
        }
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { nfdump_reader_close(self.ptr) };
        }
    }
}

fn cstr_or(p: *const c_char, default: &str) -> String {
    if p.is_null() {
        default.to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned() }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: read_flows <nfcapd-file> [max-records-to-print]");
            std::process::exit(1);
        }
    };
    let max_print: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(10);

    println!("nfdump ABI version: {}\n", unsafe { nfdump_abi_version() });

    let mut fi = FieldInfo { abi_version: ABI_VERSION, struct_size: std::mem::size_of::<FieldInfo>() as u32, name: ptr::null(), field_type: 0, size: 0 };
    if unsafe { nfdump_field_describe(field::IN_BYTES, &mut fi) } == STATUS_OK {
        println!(
            "field #{}: name={} type={} size={} (of {} fields total)\n",
            field::IN_BYTES,
            cstr_or(fi.name, "?"),
            fi.field_type,
            fi.size,
            unsafe { nfdump_field_count() }
        );
    }

    let mut reader = match Reader::open(&path) {
        Ok(r) => r,
        Err(st) => {
            eprintln!("nfdump_reader_open('{path}') failed: status={st}");
            std::process::exit(1);
        }
    };

    if let Ok(info) = reader.file_info() {
        println!(
            "file: numFlows={} numBytes={} numPackets={} ident={}\n",
            info.num_flows,
            info.num_bytes,
            info.num_packets,
            cstr_or(info.ident, "(none)")
        );
    }

    let mut count: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_packets: u64 = 0;

    loop {
        let rec = match reader.next_record() {
            Ok(Some(r)) => r,
            Ok(None) => break, // EOF
            Err(st) => {
                eprintln!("nfdump_reader_next failed: status={} error={}", st, reader.last_error());
                std::process::exit(1);
            }
        };
        count += 1;

        let in_bytes = reader.get_u64(field::IN_BYTES).unwrap_or(0);
        let in_packets = reader.get_u64(field::IN_PACKETS).unwrap_or(0);
        total_bytes += in_bytes;
        total_packets += in_packets;

        if count <= max_print {
            let proto = reader.get_u8(field::PROTO).unwrap_or(0);
            let src_port = reader.get_u16(field::SRC_PORT).unwrap_or(0);
            let dst_port = reader.get_u16(field::DST_PORT).unwrap_or(0);
            let src = reader.get_addr(field::SRC_ADDR).map(|a| a.to_string()).unwrap_or_else(|| "?".into());
            let dst = reader.get_addr(field::DST_ADDR).map(|a| a.to_string()).unwrap_or_else(|| "?".into());
            println!("#{:<6} proto={:<3} {}:{} -> {}:{}  bytes={} packets={}", rec.ordinal, proto, src, src_port, dst, dst_port, in_bytes, in_packets);
        }
    }

    println!("\n{count} records, {total_bytes} bytes, {total_packets} packets");
}
