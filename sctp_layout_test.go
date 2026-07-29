//go:build linux && !386
// +build linux,!386

package sctp

import (
	"testing"
	"unsafe"
)

// Every struct in this package that crosses the getsockopt/setsockopt boundary
// is handed to the kernel as raw memory. A size or field-offset disagreement is
// therefore silent: the kernel reads whatever bytes sit where it expects a
// field, and the caller gets a plausible-looking wrong answer rather than an
// error. That is exactly how the sctp_pdapi_event field order in this package
// was once wrong — the RFC lists the fields in a different order than the
// kernel struct, and only a C probe caught it.
//
// The numbers below were taken from offsetof() and sizeof() against
// linux/sctp.h and netinet/sctp.h on a live kernel, not from the RFC, because
// where the two disagree the kernel is what this package talks to. Reproduce
// them with testdata/layoutprobe.
//
// This test cannot detect a kernel that changes its layout — it pins the Go
// side to what was measured. Re-run the probe when targeting a new kernel.
func TestStructLayoutsMatchKernel(t *testing.T) {
	t.Run("Status", func(t *testing.T) {
		var s Status
		assertSize(t, "Status", unsafe.Sizeof(s), 176)
		assertOffset(t, "AssocID", unsafe.Offsetof(s.AssocID), 0)
		assertOffset(t, "State", unsafe.Offsetof(s.State), 4)
		assertOffset(t, "RWND", unsafe.Offsetof(s.RWND), 8)
		assertOffset(t, "Unackdata", unsafe.Offsetof(s.Unackdata), 12)
		assertOffset(t, "Penddata", unsafe.Offsetof(s.Penddata), 14)
		assertOffset(t, "Instreams", unsafe.Offsetof(s.Instreams), 16)
		assertOffset(t, "Ostreams", unsafe.Offsetof(s.Ostreams), 18)
		assertOffset(t, "FragmentationPoint", unsafe.Offsetof(s.FragmentationPoint), 20)
		assertOffset(t, "PrimaryPeerAddr", unsafe.Offsetof(s.PrimaryPeerAddr), 24)
	})

	t.Run("PeerAddrinfo", func(t *testing.T) {
		var p PeerAddrinfo
		// 152 because spinfo_address is a sockaddr_storage, which is 128 bytes.
		assertSize(t, "PeerAddrinfo", unsafe.Sizeof(p), 152)
		assertOffset(t, "AssocID", unsafe.Offsetof(p.AssocID), 0)
		assertOffset(t, "Address", unsafe.Offsetof(p.Address), 4)
		assertOffset(t, "State", unsafe.Offsetof(p.State), 132)
		assertOffset(t, "CWND", unsafe.Offsetof(p.CWND), 136)
		assertOffset(t, "SRTT", unsafe.Offsetof(p.SRTT), 140)
		assertOffset(t, "RTO", unsafe.Offsetof(p.RTO), 144)
		assertOffset(t, "MTU", unsafe.Offsetof(p.MTU), 148)
	})

	t.Run("RtoInfo", func(t *testing.T) {
		var r RtoInfo
		assertSize(t, "RtoInfo", unsafe.Sizeof(r), 16)
		assertOffset(t, "AssocID", unsafe.Offsetof(r.AssocID), 0)
		assertOffset(t, "Initial", unsafe.Offsetof(r.Initial), 4)
		assertOffset(t, "Max", unsafe.Offsetof(r.Max), 8)
		assertOffset(t, "Min", unsafe.Offsetof(r.Min), 12)
	})

	t.Run("AssocInfo", func(t *testing.T) {
		var a AssocInfo
		assertSize(t, "AssocInfo", unsafe.Sizeof(a), 20)
		assertOffset(t, "AssocID", unsafe.Offsetof(a.AssocID), 0)
		assertOffset(t, "AsocMaxRxt", unsafe.Offsetof(a.AsocMaxRxt), 4)
		assertOffset(t, "NumberPeerDestinations",
			unsafe.Offsetof(a.NumberPeerDestinations), 6)
		assertOffset(t, "PeerRwnd", unsafe.Offsetof(a.PeerRwnd), 8)
		assertOffset(t, "LocalRwnd", unsafe.Offsetof(a.LocalRwnd), 12)
		assertOffset(t, "CookieLife", unsafe.Offsetof(a.CookieLife), 16)
	})

	t.Run("InitMsg", func(t *testing.T) {
		var m InitMsg
		assertSize(t, "InitMsg", unsafe.Sizeof(m), 8)
	})

	t.Run("AssocValue", func(t *testing.T) {
		var v AssocValue
		assertSize(t, "AssocValue", unsafe.Sizeof(v), 8)
		assertOffset(t, "AssocID", unsafe.Offsetof(v.AssocID), 0)
		assertOffset(t, "AssocVal", unsafe.Offsetof(v.AssocVal), 4)
	})

	t.Run("SndRcvInfo", func(t *testing.T) {
		var s SndRcvInfo
		assertSize(t, "SndRcvInfo", unsafe.Sizeof(s), 32)
	})

	t.Run("EventSubscribe", func(t *testing.T) {
		var e EventSubscribe
		// Deliberately 10, the RFC 6458 field count, against the kernel's 14.
		// The four extra Linux fields are unreachable through this struct; a
		// short option length is accepted on set and bounds what get writes.
		// See the type's documentation.
		assertSize(t, "EventSubscribe", unsafe.Sizeof(e), 10)
	})

	t.Run("RcvInfo", func(t *testing.T) {
		var r RcvInfo
		// struct sctp_rcvinfo, RFC 6458 §5.3.5. The field order differs from
		// SndRcvInfo — TSN and CumTSN precede Context here — so these offsets are
		// what stops the two being confused as raw memory.
		assertSize(t, "RcvInfo", unsafe.Sizeof(r), 28)
		assertOffset(t, "SID", unsafe.Offsetof(r.SID), 0)
		assertOffset(t, "SSN", unsafe.Offsetof(r.SSN), 2)
		assertOffset(t, "Flags", unsafe.Offsetof(r.Flags), 4)
		assertOffset(t, "PPID", unsafe.Offsetof(r.PPID), 8)
		assertOffset(t, "TSN", unsafe.Offsetof(r.TSN), 12)
		assertOffset(t, "CumTSN", unsafe.Offsetof(r.CumTSN), 16)
		assertOffset(t, "Context", unsafe.Offsetof(r.Context), 20)
		assertOffset(t, "AssocID", unsafe.Offsetof(r.AssocID), 24)
	})

	t.Run("Event", func(t *testing.T) {
		var e Event
		assertSize(t, "Event", unsafe.Sizeof(e), 8)
	})
}

func assertSize(t *testing.T, name string, got, want uintptr) {
	t.Helper()
	if got != want {
		t.Errorf("sizeof(%s) = %d, want %d as measured against the kernel",
			name, got, want)
	}
}

func assertOffset(t *testing.T, field string, got, want uintptr) {
	t.Helper()
	if got != want {
		t.Errorf("%s at offset %d, want %d as measured against the kernel",
			field, got, want)
	}
}
