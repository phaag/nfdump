#!/usr/bin/env luajit
--[[
read_flows.lua — usage example for the nfdump read ABI from LuaJIT.

Requires LuaJIT (its `ffi` library), not stock PUC Lua, which has no
built-in FFI. LuaJIT's ffi.cdef() is close to a direct C declaration
parser, so the block below is nearly a copy of
../../../src/libnfdump/nfdump.h with the comments and the NFDUMP_API
visibility macro stripped out — nfdump.h was deliberately kept dependency-
free (see its header comment) so a binding generator like this one can
consume it almost verbatim instead of hand-translating every struct.

Usage:
    NFDUMP_LIB=/path/to/libnfdump.dylib luajit read_flows.lua nfcapd.file [max]
]]

local ffi = require("ffi")
local bit = require("bit")

ffi.cdef[[
typedef enum {
    NFDUMP_OK = 0,
    NFDUMP_EOF = 1,
    NFDUMP_ABSENT = 2,
    NFDUMP_ERR_IO = -1,
    NFDUMP_ERR_FORMAT = -2,
    NFDUMP_ERR_UNSUPPORTED = -3,
    NFDUMP_ERR_CRYPTO = -4,
    NFDUMP_ERR_INVALID_ARG = -5,
} nfdump_status_t;

typedef struct nfdump_reader_s nfdump_reader_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    const char *passphrase;
} nfdump_reader_options_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t ordinal;
    const uint8_t *data;
    uint32_t size;
} nfdump_record_view_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t numFlows;
    uint64_t numBytes;
    uint64_t numPackets;
    uint64_t msecFirstSeen;
    uint64_t msecLastSeen;
    const char *ident;
} nfdump_file_info_t;

typedef enum {
    NFDUMP_FIELD_NONE = 0,
    NFDUMP_FIELD_FIRST_SEEN, NFDUMP_FIELD_LAST_SEEN, NFDUMP_FIELD_RECEIVED,
    NFDUMP_FIELD_IP_VERSION, NFDUMP_FIELD_SRC_ADDR, NFDUMP_FIELD_DST_ADDR,
    NFDUMP_FIELD_SRC_PORT, NFDUMP_FIELD_DST_PORT, NFDUMP_FIELD_ICMP_TYPE, NFDUMP_FIELD_ICMP_CODE,
    NFDUMP_FIELD_PROTO, NFDUMP_FIELD_TCP_FLAGS, NFDUMP_FIELD_SRC_TOS, NFDUMP_FIELD_FWD_STATUS,
    NFDUMP_FIELD_IN_PACKETS, NFDUMP_FIELD_IN_BYTES, NFDUMP_FIELD_OUT_PACKETS, NFDUMP_FIELD_OUT_BYTES,
    NFDUMP_FIELD_AGGR_FLOWS,
    NFDUMP_FIELD_INPUT_IF, NFDUMP_FIELD_OUTPUT_IF, NFDUMP_FIELD_SRC_AS, NFDUMP_FIELD_DST_AS,
    NFDUMP_FIELD_SRC_VLAN, NFDUMP_FIELD_DST_VLAN,
    NFDUMP_FIELD_SRC_MASK, NFDUMP_FIELD_DST_MASK, NFDUMP_FIELD_DIRECTION, NFDUMP_FIELD_DST_TOS,
    NFDUMP_FIELD_FLOW_END_REASON,
    NFDUMP_FIELD_EXPORTER_ID, NFDUMP_FIELD_ENGINE_TYPE, NFDUMP_FIELD_ENGINE_ID, NFDUMP_FIELD_NF_VERSION,
    NFDUMP_FIELD_MAX
} nfdump_field_id_t;

typedef enum { NFDUMP_T_U8 = 1, NFDUMP_T_U16, NFDUMP_T_U32, NFDUMP_T_U64, NFDUMP_T_IPV6 } nfdump_field_type_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    const char *name;
    nfdump_field_type_t type;
    uint16_t size;
} nfdump_field_info_t;

uint32_t nfdump_abi_version(void);
nfdump_status_t nfdump_reader_open(const char *path, const nfdump_reader_options_t *options, nfdump_reader_t **out_reader);
void nfdump_reader_close(nfdump_reader_t *reader);
const char *nfdump_reader_last_error(const nfdump_reader_t *reader);
nfdump_status_t nfdump_reader_next(nfdump_reader_t *reader, nfdump_record_view_t *record);
nfdump_status_t nfdump_reader_file_info(const nfdump_reader_t *reader, nfdump_file_info_t *out);
size_t nfdump_field_count(void);
nfdump_status_t nfdump_field_describe(nfdump_field_id_t field, nfdump_field_info_t *out);
nfdump_status_t nfdump_record_get(nfdump_reader_t *reader, nfdump_field_id_t field, void *out, size_t out_size);
]]

-- ffi.load()'s underlying dlopen() is lazily bound: it happily "succeeds"
-- against a library that doesn't actually export what we need (observed
-- for real: a stale, unrelated libnfdump at a standard path loaded
-- without error, then crashed deep inside unrelated code the moment a
-- missing symbol was first called). So every candidate below is verified
-- by actually calling nfdump_abi_version() before being trusted, not just
-- by whether ffi.load() itself raised.
local function verified(lib)
    local ok, version = pcall(function() return lib.nfdump_abi_version() end)
    if ok and type(version) == "number" and version >= 1 then return lib end
    return nil
end

-- Loads libnfdump: an explicit NFDUMP_LIB path first, then the installed
-- library found the normal way for the platform (a bare name lets the
-- dynamic loader's own search - ldconfig on Linux, DYLD_FALLBACK_LIBRARY_
-- PATH incl. /usr/local/lib on macOS - find it), then the default install
-- prefix (/usr/local) as a last resort. Does not look inside any nfdump
-- source tree - if nfdump isn't installed under one of these, this
-- errors rather than guess further.
local function open_lib()
    local explicit = os.getenv("NFDUMP_LIB")
    if explicit then
        -- Trust the caller's own path, but still verify it - a clear error
        -- now beats a cryptic crash later if it points at the wrong file.
        local good = verified(ffi.load(explicit))
        if not good then
            error("NFDUMP_LIB=" .. explicit .. " loaded but does not look like libnfdump")
        end
        return good
    end

    local ok, lib = pcall(ffi.load, "nfdump")
    if ok then
        local good = verified(lib)
        if good then return good end
    end

    -- The bare-name search missed it (or found something that wouldn't
    -- load or verify) - try the default install prefix directly. An
    -- installed libnfdump resolves its own libnffile dependency with no
    -- extra help.
    local prefix = os.getenv("PREFIX") or "/usr/local"
    for _, name in ipairs({ "libnfdump.dylib", "libnfdump.so" }) do
        local candidate = prefix .. "/lib/" .. name
        local f = io.open(candidate, "rb")
        if f then
            f:close()
            local pok, plib = pcall(ffi.load, candidate)
            if pok then
                local good = verified(plib)
                if good then return good end
            end
        end
    end

    error("could not locate a working libnfdump; install nfdump (a bare "
        .. "'nfdump' load should then find it), or set "
        .. "NFDUMP_LIB=/path/to/libnfdump.{so,dylib}")
end

local C = open_lib()

local function checked(status, context)
    if status ~= C.NFDUMP_OK then
        error(string.format("%s failed: status=%d", context, tonumber(status)))
    end
end

-- addr: 16-byte network-order buffer -> dotted/colon string, unwrapping
-- the IPv4-mapped form nfdump.h documents (::ffff:a.b.c.d).
local function addr_to_string(buf)
    local b = ffi.cast("uint8_t*", buf)
    local isV4Mapped = true
    for i = 0, 9 do
        if b[i] ~= 0 then isV4Mapped = false; break end
    end
    if isV4Mapped and b[10] == 0xff and b[11] == 0xff then
        return string.format("%d.%d.%d.%d", b[12], b[13], b[14], b[15])
    end
    local parts = {}
    for i = 0, 7 do
        parts[#parts + 1] = string.format("%x", bit.bor(bit.lshift(b[2 * i], 8), b[2 * i + 1]))
    end
    return table.concat(parts, ":")
end

local function main(argv)
    if #argv < 1 then
        io.stderr:write("usage: read_flows.lua <nfcapd-file> [max-records-to-print]\n")
        os.exit(1)
    end
    local path = argv[1]
    local maxPrint = tonumber(argv[2]) or 10

    print(string.format("nfdump ABI version: %d\n", C.nfdump_abi_version()))

    local fi = ffi.new("nfdump_field_info_t")
    fi.struct_size = ffi.sizeof("nfdump_field_info_t")
    if C.nfdump_field_describe(C.NFDUMP_FIELD_IN_BYTES, fi) == C.NFDUMP_OK then
        print(string.format("field #%d: name=%s type=%d size=%d (of %d fields total)\n",
            tonumber(C.NFDUMP_FIELD_IN_BYTES), ffi.string(fi.name), tonumber(fi.type), fi.size, tonumber(C.nfdump_field_count())))
    end

    local readerPtr = ffi.new("nfdump_reader_t*[1]")
    local st = C.nfdump_reader_open(path, nil, readerPtr)
    if st ~= C.NFDUMP_OK then
        io.stderr:write(string.format("nfdump_reader_open('%s') failed: status=%d\n", path, tonumber(st)))
        os.exit(1)
    end
    local reader = readerPtr[0]

    local info = ffi.new("nfdump_file_info_t")
    info.struct_size = ffi.sizeof("nfdump_file_info_t")
    if C.nfdump_reader_file_info(reader, info) == C.NFDUMP_OK then
        -- tonumber() on a uint64_t cdata goes through a Lua double, which is exact up to
        -- 2^53 - plenty for a flow/byte/packet count, just not the right tool near uint64 max.
        print(string.format("file: numFlows=%d numBytes=%d numPackets=%d ident=%s\n",
            tonumber(info.numFlows), tonumber(info.numBytes), tonumber(info.numPackets),
            info.ident ~= nil and ffi.string(info.ident) or "(none)"))
    end

    local u64 = ffi.new("uint64_t[1]")
    local u16 = ffi.new("uint16_t[1]")
    local u8 = ffi.new("uint8_t[1]")
    local addr = ffi.new("uint8_t[16]")

    local function getU64(field) return C.nfdump_record_get(reader, field, u64, 8) == C.NFDUMP_OK and u64[0] or 0 end
    local function getU16(field) return C.nfdump_record_get(reader, field, u16, 2) == C.NFDUMP_OK and u16[0] or 0 end
    local function getU8(field) return C.nfdump_record_get(reader, field, u8, 1) == C.NFDUMP_OK and u8[0] or 0 end
    local function getAddr(field)
        if C.nfdump_record_get(reader, field, addr, 16) ~= C.NFDUMP_OK then return "?" end
        return addr_to_string(addr)
    end

    local rec = ffi.new("nfdump_record_view_t")
    local count, totalBytes, totalPackets = 0, 0ULL, 0ULL

    while true do
        st = C.nfdump_reader_next(reader, rec)
        if st == C.NFDUMP_EOF then break end
        if st ~= C.NFDUMP_OK then
            io.stderr:write(string.format("nfdump_reader_next failed: status=%d error=%s\n",
                tonumber(st), ffi.string(C.nfdump_reader_last_error(reader))))
            os.exit(1)
        end
        count = count + 1

        local inBytes, inPackets = getU64(C.NFDUMP_FIELD_IN_BYTES), getU64(C.NFDUMP_FIELD_IN_PACKETS)
        totalBytes = totalBytes + inBytes
        totalPackets = totalPackets + inPackets

        if count <= maxPrint then
            local proto = getU8(C.NFDUMP_FIELD_PROTO)
            local srcPort, dstPort = getU16(C.NFDUMP_FIELD_SRC_PORT), getU16(C.NFDUMP_FIELD_DST_PORT)
            local src, dst = getAddr(C.NFDUMP_FIELD_SRC_ADDR), getAddr(C.NFDUMP_FIELD_DST_ADDR)
            print(string.format("#%-6d proto=%-3d %s:%d -> %s:%d  bytes=%d packets=%d",
                tonumber(rec.ordinal), tonumber(proto), src, tonumber(srcPort), dst, tonumber(dstPort),
                tonumber(inBytes), tonumber(inPackets)))
        end
    end

    C.nfdump_reader_close(reader)
    print(string.format("\n%d records, %d bytes, %d packets", count, tonumber(totalBytes), tonumber(totalPackets)))
end

main(arg)
