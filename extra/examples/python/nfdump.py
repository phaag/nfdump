"""
nfdump.py — a small ctypes binding for the nfdump read ABI.

This hand-writes the ctypes.Structure/function-prototype mirrors of
../../../src/libnfdump/nfdump.h. ctypes has no way to parse a C header
directly (cffi/ctypesgen can, if that route is preferred) so the struct
layouts below must be kept in sync with nfdump.h by hand. ctypes.Structure
uses the platform's natural C struct alignment by default (no _pack_ set
here), which is what nfdump.h's structs assume too, so field order/types
below matching the header is the only thing that matters for layout to
line up.

Usage:
    import nfdump

    with nfdump.Reader("nfcapd.202601010000") as r:
        print(r.file_info())
        for rec in r:
            print(rec.ordinal, rec.get_u64(nfdump.FIELD_IN_BYTES))
"""

import ctypes
import ctypes.util
import os
import ipaddress


# ---------------------------------------------------------------------
# nfdump_status_t
# ---------------------------------------------------------------------
OK = 0
EOF = 1
ABSENT = 2
ERR_IO = -1
ERR_FORMAT = -2
ERR_UNSUPPORTED = -3
ERR_CRYPTO = -4
ERR_INVALID_ARG = -5

_STATUS_NAMES = {
    OK: "OK", EOF: "EOF", ABSENT: "ABSENT", ERR_IO: "ERR_IO",
    ERR_FORMAT: "ERR_FORMAT", ERR_UNSUPPORTED: "ERR_UNSUPPORTED",
    ERR_CRYPTO: "ERR_CRYPTO", ERR_INVALID_ARG: "ERR_INVALID_ARG",
}


class NfdumpError(Exception):
    """Raised for any nfdump_status_t other than OK/EOF/ABSENT."""

    def __init__(self, status, detail=""):
        self.status = status
        name = _STATUS_NAMES.get(status, str(status))
        msg = f"nfdump error: {name}"
        if detail:
            msg += f" ({detail})"
        super().__init__(msg)


# ---------------------------------------------------------------------
# nfdump_field_id_t - must match the enum in nfdump.h exactly: same
# order, same values (1-based, append-only). Never renumber.
# ---------------------------------------------------------------------
FIELD_NONE = 0
FIELD_FIRST_SEEN = 1
FIELD_LAST_SEEN = 2
FIELD_RECEIVED = 3
FIELD_IP_VERSION = 4
FIELD_SRC_ADDR = 5
FIELD_DST_ADDR = 6
FIELD_SRC_PORT = 7
FIELD_DST_PORT = 8
FIELD_ICMP_TYPE = 9
FIELD_ICMP_CODE = 10
FIELD_PROTO = 11
FIELD_TCP_FLAGS = 12
FIELD_SRC_TOS = 13
FIELD_FWD_STATUS = 14
FIELD_IN_PACKETS = 15
FIELD_IN_BYTES = 16
FIELD_OUT_PACKETS = 17
FIELD_OUT_BYTES = 18
FIELD_AGGR_FLOWS = 19
FIELD_INPUT_IF = 20
FIELD_OUTPUT_IF = 21
FIELD_SRC_AS = 22
FIELD_DST_AS = 23
FIELD_SRC_VLAN = 24
FIELD_DST_VLAN = 25
FIELD_SRC_MASK = 26
FIELD_DST_MASK = 27
FIELD_DIRECTION = 28
FIELD_DST_TOS = 29
FIELD_FLOW_END_REASON = 30
FIELD_EXPORTER_ID = 31
FIELD_ENGINE_TYPE = 32
FIELD_ENGINE_ID = 33
FIELD_NF_VERSION = 34
FIELD_MAX = 35

# nfdump_field_type_t
T_U8, T_U16, T_U32, T_U64, T_IPV6 = 1, 2, 3, 4, 5

ABI_VERSION = 1


# ---------------------------------------------------------------------
# ctypes struct mirrors - field order/types must match nfdump.h exactly.
# ---------------------------------------------------------------------
class _NfdumpReader(ctypes.Structure):
    """Opaque - never dereferenced from Python, only passed around as a pointer."""


class ReaderOptions(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("struct_size", ctypes.c_uint32),
        ("passphrase", ctypes.c_char_p),
    ]


class RecordView(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("struct_size", ctypes.c_uint32),
        ("ordinal", ctypes.c_uint64),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("size", ctypes.c_uint32),
    ]


class FileInfo(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("struct_size", ctypes.c_uint32),
        ("numFlows", ctypes.c_uint64),
        ("numBytes", ctypes.c_uint64),
        ("numPackets", ctypes.c_uint64),
        ("msecFirstSeen", ctypes.c_uint64),
        ("msecLastSeen", ctypes.c_uint64),
        ("ident", ctypes.c_char_p),
    ]

    def __repr__(self):
        ident = self.ident.decode() if self.ident else None
        return (f"FileInfo(numFlows={self.numFlows}, numBytes={self.numBytes}, "
                f"numPackets={self.numPackets}, ident={ident!r})")


class FieldInfo(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("struct_size", ctypes.c_uint32),
        ("name", ctypes.c_char_p),
        ("type", ctypes.c_int),  # nfdump_field_type_t - plain C enum, 4 bytes on every supported ABI
        ("size", ctypes.c_uint16),
    ]


# ---------------------------------------------------------------------
# library loading
# ---------------------------------------------------------------------
def _load_library():
    """
    Loads libnfdump: an explicit NFDUMP_LIB path first, then the installed
    library found the normal way for the platform, then the default
    install prefix (/usr/local) as a last resort. Does not look inside any
    nfdump source tree - if nfdump isn't installed under one of these, this
    raises rather than guess further.
    """
    explicit = os.environ.get("NFDUMP_LIB")
    if explicit:
        return ctypes.CDLL(explicit)

    found = ctypes.util.find_library("nfdump")
    if found:
        try:
            return ctypes.CDLL(found)
        except OSError:
            # Found *a* library by that name, but it wouldn't load - e.g. an
            # unrelated or stale library at a standard path. Fall through
            # rather than crash on what might not even be nfdump.
            pass

    # find_library() missed it, or found something that wouldn't load -
    # try the default install prefix directly. An installed libnfdump
    # resolves its own libnffile dependency with no extra help.
    prefix = os.environ.get("PREFIX", "/usr/local")
    for name in ("libnfdump.dylib", "libnfdump.so"):
        candidate = os.path.join(prefix, "lib", name)
        if os.path.exists(candidate):
            try:
                return ctypes.CDLL(candidate)
            except OSError:
                pass

    raise OSError(
        "could not locate libnfdump; install nfdump (pkg-config nfdump "
        "should then find it), or set NFDUMP_LIB=/path/to/libnfdump.{so,dylib}"
    )


_lib = _load_library()

_lib.nfdump_abi_version.argtypes = []
_lib.nfdump_abi_version.restype = ctypes.c_uint32

_lib.nfdump_reader_open.argtypes = [
    ctypes.c_char_p, ctypes.POINTER(ReaderOptions), ctypes.POINTER(ctypes.POINTER(_NfdumpReader)),
]
_lib.nfdump_reader_open.restype = ctypes.c_int

_lib.nfdump_reader_close.argtypes = [ctypes.POINTER(_NfdumpReader)]
_lib.nfdump_reader_close.restype = None

_lib.nfdump_reader_last_error.argtypes = [ctypes.POINTER(_NfdumpReader)]
_lib.nfdump_reader_last_error.restype = ctypes.c_char_p

_lib.nfdump_reader_next.argtypes = [ctypes.POINTER(_NfdumpReader), ctypes.POINTER(RecordView)]
_lib.nfdump_reader_next.restype = ctypes.c_int

_lib.nfdump_reader_file_info.argtypes = [ctypes.POINTER(_NfdumpReader), ctypes.POINTER(FileInfo)]
_lib.nfdump_reader_file_info.restype = ctypes.c_int

_lib.nfdump_field_count.argtypes = []
_lib.nfdump_field_count.restype = ctypes.c_size_t

_lib.nfdump_field_describe.argtypes = [ctypes.c_int, ctypes.POINTER(FieldInfo)]
_lib.nfdump_field_describe.restype = ctypes.c_int

_lib.nfdump_record_get.argtypes = [ctypes.POINTER(_NfdumpReader), ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
_lib.nfdump_record_get.restype = ctypes.c_int


def abi_version():
    return _lib.nfdump_abi_version()


def field_count():
    return _lib.nfdump_field_count()


def field_describe(field):
    fi = FieldInfo(struct_size=ctypes.sizeof(FieldInfo))
    st = _lib.nfdump_field_describe(field, ctypes.byref(fi))
    if st != OK:
        raise NfdumpError(st)
    return fi.name.decode(), fi.type, fi.size


_ADDR_TYPES = {
    T_U8: ctypes.c_uint8, T_U16: ctypes.c_uint16, T_U32: ctypes.c_uint32, T_U64: ctypes.c_uint64,
}


class Record:
    """A thin, per-record convenience wrapper. Valid only until the reader's
    next __next__()/close() call, exactly like the underlying
    nfdump_record_view_t - see nfdump.h."""

    __slots__ = ("_reader", "ordinal", "raw")

    def __init__(self, reader, view):
        self._reader = reader
        self.ordinal = view.ordinal
        self.raw = ctypes.string_at(view.data, view.size)  # opaque bytes, see nfdump.h

    def _get(self, field, ctype):
        buf = ctype()
        st = _lib.nfdump_record_get(self._reader, field, ctypes.byref(buf), ctypes.sizeof(buf))
        if st == ABSENT:
            return None
        if st != OK:
            raise NfdumpError(st, nfdump_reader_last_error_str(self._reader))
        return buf.value

    def get_u8(self, field):
        return self._get(field, ctypes.c_uint8)

    def get_u16(self, field):
        return self._get(field, ctypes.c_uint16)

    def get_u32(self, field):
        return self._get(field, ctypes.c_uint32)

    def get_u64(self, field):
        return self._get(field, ctypes.c_uint64)

    def get_addr(self, field):
        """Returns an ipaddress.IPv4Address/IPv6Address, or None if absent."""
        buf = (ctypes.c_uint8 * 16)()
        st = _lib.nfdump_record_get(self._reader, field, ctypes.byref(buf), 16)
        if st == ABSENT:
            return None
        if st != OK:
            raise NfdumpError(st, nfdump_reader_last_error_str(self._reader))
        raw = bytes(buf)
        addr = ipaddress.ip_address(raw)
        return addr.ipv4_mapped or addr  # unwrap ::ffff:a.b.c.d back to plain IPv4, like nfdump.h documents

    def __repr__(self):
        return f"Record(ordinal={self.ordinal}, size={len(self.raw)})"


def nfdump_reader_last_error_str(reader_ptr):
    s = _lib.nfdump_reader_last_error(reader_ptr)
    return s.decode() if s else ""


class Reader:
    """
    with nfdump.Reader(path) as r:
        for rec in r:
            ...

    Mirrors nfdump_reader_open()/nfdump_reader_next()/nfdump_reader_close()
    one-to-one; see nfdump.h for the exact contract (a Record is a borrowed
    view valid only until the next iteration step).
    """

    def __init__(self, path, passphrase=None):
        self._reader = ctypes.POINTER(_NfdumpReader)()
        opts = None
        if passphrase:
            opts = ReaderOptions(abi_version=ABI_VERSION, struct_size=ctypes.sizeof(ReaderOptions),
                                  passphrase=passphrase.encode())
        st = _lib.nfdump_reader_open(path.encode(), ctypes.byref(opts) if opts else None, ctypes.byref(self._reader))
        if st != OK:
            # fails closed - see nfdump_reader_open() in nfdump.h: nothing to close on failure.
            raise NfdumpError(st, f"open('{path}') failed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self):
        if self._reader:
            _lib.nfdump_reader_close(self._reader)
            self._reader = ctypes.POINTER(_NfdumpReader)()

    def file_info(self):
        info = FileInfo(struct_size=ctypes.sizeof(FileInfo))
        st = _lib.nfdump_reader_file_info(self._reader, ctypes.byref(info))
        if st != OK:
            raise NfdumpError(st)
        return info

    def __iter__(self):
        return self

    def __next__(self):
        view = RecordView()
        st = _lib.nfdump_reader_next(self._reader, ctypes.byref(view))
        if st == EOF:
            raise StopIteration
        if st != OK:
            raise NfdumpError(st, nfdump_reader_last_error_str(self._reader))
        return Record(self._reader, view)
