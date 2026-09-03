// read_flows — usage example for the nfdump read ABI from Go, via cgo.
//
// Unlike the Python (ctypes) and Rust examples, this one does not
// hand-duplicate nfdump.h's struct layouts: cgo runs a real C compiler
// over the `#include "nfdump.h"` below and generates matching Go types
// itself (C.nfdump_record_view_t, C.nfdump_field_id_t, ...), so there is
// nothing here to keep in sync by hand if the header changes.
//
// Build/run: see the README in this directory. Unlike the C/Rust/Python/
// Lua examples, this one can't automatically prefer pkg-config and fall
// back to a default path: cgo's #cgo directives are static, and
// "#cgo pkg-config: nfdump" is a hard build failure (not a soft,
// skippable check) when pkg-config can't find the package - confirmed
// while writing this example. So this defaults to the default install
// prefix (/usr/local) directly, like the other examples' own fallback -
// this file doesn't reach into the nfdump source tree at all. If nfdump
// is installed somewhere pkg-config knows about but /usr/local doesn't,
// swap the two lines below for the single "#cgo pkg-config: nfdump"
// alternative instead.
package main

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lnfdump
#include <stdlib.h>
#include "nfdump.h"
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"unsafe"
)

// reader wraps a *C.nfdump_reader_t; Close() must be called exactly once
// (nfdump_reader_open() fails closed - see nfdump.h - so there is never a
// reader to close on a failed open()).
type reader struct {
	ptr *C.nfdump_reader_t
}

func openReader(path string) (*reader, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var ptr *C.nfdump_reader_t
	st := C.nfdump_reader_open(cpath, nil, &ptr)
	if st != C.NFDUMP_OK {
		return nil, fmt.Errorf("nfdump_reader_open(%q) failed: status=%d", path, int(st))
	}
	return &reader{ptr: ptr}, nil
}

func (r *reader) Close() {
	C.nfdump_reader_close(r.ptr)
}

func (r *reader) lastError() string {
	return C.GoString(C.nfdump_reader_last_error(r.ptr))
}

func (r *reader) fileInfo() (C.nfdump_file_info_t, error) {
	info := C.nfdump_file_info_t{
		struct_size: C.uint32_t(unsafe.Sizeof(C.nfdump_file_info_t{})),
	}
	st := C.nfdump_reader_file_info(r.ptr, &info)
	if st != C.NFDUMP_OK {
		return info, fmt.Errorf("nfdump_reader_file_info failed: status=%d", int(st))
	}
	return info, nil
}

// next returns (view, true, nil) for a record, (_, false, nil) at EOF, or
// an error on a corrupt file - mirrors nfdump_reader_next()'s three-way
// NFDUMP_OK/NFDUMP_EOF/NFDUMP_ERR_* contract from nfdump.h.
func (r *reader) next() (C.nfdump_record_view_t, bool, error) {
	var rec C.nfdump_record_view_t
	st := C.nfdump_reader_next(r.ptr, &rec)
	switch st {
	case C.NFDUMP_OK:
		return rec, true, nil
	case C.NFDUMP_EOF:
		return rec, false, nil
	default:
		return rec, false, fmt.Errorf("nfdump_reader_next failed: status=%d error=%s", int(st), r.lastError())
	}
}

// getScalar reads a fixed-size field (U8/U16/U32/U64) into a Go value of
// matching size. Returns ok=false on NFDUMP_ABSENT or any error.
func getScalar[T ~uint8 | ~uint16 | ~uint32 | ~uint64](r *reader, field C.nfdump_field_id_t) (T, bool) {
	var v T
	st := C.nfdump_record_get(r.ptr, field, unsafe.Pointer(&v), C.size_t(unsafe.Sizeof(v)))
	return v, st == C.NFDUMP_OK
}

func getAddr(r *reader, field C.nfdump_field_id_t) net.IP {
	var buf [16]byte
	st := C.nfdump_record_get(r.ptr, field, unsafe.Pointer(&buf[0]), 16)
	if st != C.NFDUMP_OK {
		return nil
	}
	ip := net.IP(buf[:])
	if v4 := ip.To4(); v4 != nil { // unwraps ::ffff:a.b.c.d, per nfdump.h's documented encoding
		return v4
	}
	return ip
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <nfcapd-file> [max-records-to-print]\n", os.Args[0])
		os.Exit(1)
	}
	path := os.Args[1]
	maxPrint := int64(10)
	if len(os.Args) > 2 {
		if n, err := strconv.ParseInt(os.Args[2], 10, 64); err == nil {
			maxPrint = n
		}
	}

	fmt.Printf("nfdump ABI version: %d\n\n", uint32(C.nfdump_abi_version()))

	fi := C.nfdump_field_info_t{struct_size: C.uint32_t(unsafe.Sizeof(C.nfdump_field_info_t{}))}
	if C.nfdump_field_describe(C.NFDUMP_FIELD_IN_BYTES, &fi) == C.NFDUMP_OK {
		fmt.Printf("field #%d: name=%s type=%d size=%d (of %d fields total)\n\n",
			C.NFDUMP_FIELD_IN_BYTES, C.GoString(fi.name), fi._type, fi.size, C.nfdump_field_count())
	}

	r, err := openReader(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer r.Close()

	if info, err := r.fileInfo(); err == nil {
		ident := "(none)"
		if info.ident != nil {
			ident = C.GoString(info.ident)
		}
		fmt.Printf("file: numFlows=%d numBytes=%d numPackets=%d ident=%s\n\n", info.numFlows, info.numBytes, info.numPackets, ident)
	}

	var count, totalBytes, totalPackets uint64
	for {
		rec, ok, err := r.next()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if !ok {
			break // EOF
		}
		count++

		inBytes, _ := getScalar[uint64](r, C.NFDUMP_FIELD_IN_BYTES)
		inPackets, _ := getScalar[uint64](r, C.NFDUMP_FIELD_IN_PACKETS)
		totalBytes += inBytes
		totalPackets += inPackets

		if int64(count) <= maxPrint {
			proto, _ := getScalar[uint8](r, C.NFDUMP_FIELD_PROTO)
			srcPort, _ := getScalar[uint16](r, C.NFDUMP_FIELD_SRC_PORT)
			dstPort, _ := getScalar[uint16](r, C.NFDUMP_FIELD_DST_PORT)
			src, dst := getAddr(r, C.NFDUMP_FIELD_SRC_ADDR), getAddr(r, C.NFDUMP_FIELD_DST_ADDR)

			fmt.Printf("#%-6d proto=%-3d %s:%d -> %s:%d  bytes=%d packets=%d\n",
				uint64(rec.ordinal), proto, src, srcPort, dst, dstPort, inBytes, inPackets)
		}
	}

	fmt.Printf("\n%d records, %d bytes, %d packets\n", count, totalBytes, totalPackets)
}
