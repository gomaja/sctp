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

	t.Run("SndInfo", func(t *testing.T) {
		var s SndInfo
		// struct sctp_sndinfo, RFC 6458 §5.3.4. The kernel rejects a short
		// SCTP_DEFAULT_SNDINFO with EINVAL rather than accepting it the way it
		// does SCTP_EVENTS, so this size has to be exact or every
		// SetDefaultSndInfo call fails.
		assertSize(t, "SndInfo", unsafe.Sizeof(s), 16)
		assertOffset(t, "SID", unsafe.Offsetof(s.SID), 0)
		assertOffset(t, "Flags", unsafe.Offsetof(s.Flags), 2)
		assertOffset(t, "PPID", unsafe.Offsetof(s.PPID), 4)
		assertOffset(t, "Context", unsafe.Offsetof(s.Context), 8)
		assertOffset(t, "AssocID", unsafe.Offsetof(s.AssocID), 12)
	})

	t.Run("DefaultPrInfo", func(t *testing.T) {
		var p DefaultPrInfo
		// struct sctp_default_prinfo, RFC 7496 §4.1. The C struct ends with a
		// __u16 and is padded to 12. Go's own alignment rules produce 12 with
		// or without the explicit trailing pad in the Go struct, so this
		// assertion pins the size but cannot detect the pad's removal.
		assertSize(t, "DefaultPrInfo", unsafe.Sizeof(p), 12)
		assertOffset(t, "AssocID", unsafe.Offsetof(p.AssocID), 0)
		assertOffset(t, "Value", unsafe.Offsetof(p.Value), 4)
		assertOffset(t, "Policy", unsafe.Offsetof(p.Policy), 8)
	})

	t.Run("PrStatus", func(t *testing.T) {
		var p PrStatus
		// struct sctp_prstatus, RFC 7496 §4.4. The two __u64 counters force
		// 8-byte alignment, so there are 2 pad bytes after Policy that Go
		// inserts on its own.
		assertSize(t, "PrStatus", unsafe.Sizeof(p), 24)
		assertOffset(t, "AssocID", unsafe.Offsetof(p.AssocID), 0)
		assertOffset(t, "SID", unsafe.Offsetof(p.SID), 4)
		assertOffset(t, "Policy", unsafe.Offsetof(p.Policy), 6)
		assertOffset(t, "AbandonedUnsent", unsafe.Offsetof(p.AbandonedUnsent), 8)
		assertOffset(t, "AbandonedSent", unsafe.Offsetof(p.AbandonedSent), 16)
	})

	// PeerAddrThlds, PeerAddrThldsV2, UDPEncaps, ProbeInterval and the address
	// half of AssocStats are not checked here. Their C layout depends on the
	// word size — the sockaddr_storage they hold is not inside a packed struct,
	// so it keeps the alignment of the unsigned long within it — and a
	// unsafe.Offsetof assertion against the Go struct would only ever describe
	// the host this runs on. They are marshalled through explicit offsets
	// instead, and pinned by TestSockaddrStorageOptionLayouts, which asserts
	// the numbers for the target it is compiled for.

	t.Run("AssocStats", func(t *testing.T) {
		// struct sctp_assoc_stats. Linux-specific, no RFC counterpart. The
		// counters are the part with a fixed layout: 256 bytes overall and
		// sas_maxrto at 136 on both word sizes, with only sas_obs_rto_ipaddr
		// moving between them — at 8 on a 64-bit kernel and 4 on a 32-bit one,
		// the difference absorbed by padding in front of the counters. So the
		// size is identical either way and no length check can tell them apart.
		assertSize(t, "AssocStats counters", assocStatsCounters, 136)
		assertSize(t, "AssocStats", assocStatsSize, 256)

		// Drive the decoder with a buffer laid out the way the kernel lays one
		// out, giving every counter a distinct value so a shifted read shows up
		// as the neighbouring field rather than as a plausible number.
		b := make([]byte, assocStatsSize)
		nativeEndian.PutUint32(b[0:], 0x11223344)
		for i := 0; i < 128; i++ {
			b[int(ssAddrOffset)+i] = byte(i)
		}
		for i := 0; i < 15; i++ {
			nativeEndian.PutUint64(b[assocStatsCounters+8*i:], uint64(0xA000+i))
		}

		var s AssocStats
		s.unmarshal(b)

		if s.AssocID != 0x11223344 {
			t.Errorf("AssocID = %#x, want 0x11223344", s.AssocID)
		}
		if s.ObsRtoIPAddr[0] != 0 || s.ObsRtoIPAddr[127] != 127 {
			t.Errorf("ObsRtoIPAddr was not read from offset %d: first=%d last=%d",
				ssAddrOffset, s.ObsRtoIPAddr[0], s.ObsRtoIPAddr[127])
		}
		for _, tc := range []struct {
			name string
			got  uint64
			idx  int
		}{
			{"MaxRto", s.MaxRto, 0},
			{"ISacks", s.ISacks, 1}, {"OSacks", s.OSacks, 2},
			{"OPackets", s.OPackets, 3}, {"IPackets", s.IPackets, 4},
			{"RtxChunks", s.RtxChunks, 5},
			{"OutOfSeqTsns", s.OutOfSeqTsns, 6},
			{"IDupChunks", s.IDupChunks, 7},
			{"GapCnt", s.GapCnt, 8},
			{"OUodChunks", s.OUodChunks, 9}, {"IUodChunks", s.IUodChunks, 10},
			{"OOdChunks", s.OOdChunks, 11}, {"IOdChunks", s.IOdChunks, 12},
			{"OCtrlChunks", s.OCtrlChunks, 13}, {"ICtrlChunks", s.ICtrlChunks, 14},
		} {
			if want := uint64(0xA000 + tc.idx); tc.got != want {
				t.Errorf("%s = %#x, want %#x (counter %d at offset %d)",
					tc.name, tc.got, want, tc.idx, assocStatsCounters+8*tc.idx)
			}
		}
	})

	t.Run("AddStreamsReq", func(t *testing.T) {
		var as AddStreamsReq
		// struct sctp_add_streams, RFC 6525 §6.3.4.
		assertSize(t, "AddStreamsReq", unsafe.Sizeof(as), 8)
		assertOffset(t, "AssocID", unsafe.Offsetof(as.AssocID), 0)
		assertOffset(t, "InStreams", unsafe.Offsetof(as.InStreams), 4)
		assertOffset(t, "OutStreams", unsafe.Offsetof(as.OutStreams), 6)
	})

	t.Run("PrInfo", func(t *testing.T) {
		var p PrInfo
		// struct sctp_prinfo, RFC 6458 §5.3.7. A __u16 followed by a __u32, so
		// the value sits at 4 and the struct is 8 — not the 6 a naive reading
		// gives. Unlike the pads in DefaultPrInfo and AuthKeyID, this one is
		// load-bearing: Go would otherwise place Value at offset 2.
		assertSize(t, "PrInfo", unsafe.Sizeof(p), 8)
		assertOffset(t, "Policy", unsafe.Offsetof(p.Policy), 0)
		assertOffset(t, "Value", unsafe.Offsetof(p.Value), 4)
	})

	t.Run("AuthInfo", func(t *testing.T) {
		var a AuthInfo
		// struct sctp_authinfo, RFC 6458 §5.3.8. A bare __u16, so 2 bytes with
		// no padding — the kernel accepts it at that exact length.
		assertSize(t, "AuthInfo", unsafe.Sizeof(a), 2)
		assertOffset(t, "KeyNumber", unsafe.Offsetof(a.KeyNumber), 0)
	})

	t.Run("AuthKeyID", func(t *testing.T) {
		var id AuthKeyID
		// struct sctp_authkeyid, RFC 6458 §8.1.18 — a sockets API struct, so it
		// is defined by RFC 6458 and not by RFC 4895, which the AUTH options
		// otherwise implement. §8.3.4 and §8.3.5 reuse it. The C declaration is a
		// sctp_assoc_t plus a __u16, which is 6 bytes, but the kernel returns
		// and expects 8 — measured with testdata/optprobe. Go's alignment gives
		// 8 with or without the struct's explicit pad, so this pins the size
		// the kernel needs but does not police the pad itself.
		assertSize(t, "AuthKeyID", unsafe.Sizeof(id), 8)
		assertOffset(t, "AssocID", unsafe.Offsetof(id.AssocID), 0)
		assertOffset(t, "KeyNumber", unsafe.Offsetof(id.KeyNumber), 4)
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
