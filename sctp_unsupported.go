//go:build !linux || (linux && 386)
// +build !linux linux,386

// Copyright 2019 Wataru Ishida. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sctp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
)

// ErrUnsupported is returned by every entry point on a platform without SCTP.
//
// It wraps errors.ErrUnsupported, so the generic check works as well as the
// specific one:
//
//	errors.Is(err, sctp.ErrUnsupported)   // this package
//	errors.Is(err, errors.ErrUnsupported) // any package
//
// It did not always do so, and the shared name made that easy to miss: a caller
// writing the portable check got false and concluded the failure was something
// other than "this platform has no SCTP". Comparing with == still works, since
// this is the same sentinel value; only its Is behaviour changed.
var ErrUnsupported = fmt.Errorf("SCTP is unsupported on %s/%s: %w",
	runtime.GOOS, runtime.GOARCH, errors.ErrUnsupported)

func setsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return 0, 0, ErrUnsupported
}

func getsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return 0, 0, ErrUnsupported
}

func (c *SCTPConn) SCTPWrite(b []byte, info *SndRcvInfo) (int, error) {
	return 0, ErrUnsupported
}

func (c *SCTPConn) SCTPWriteInfo(b []byte, info *SndInfo, pr *PrInfo, auth *AuthInfo) (int, error) {
	return 0, ErrUnsupported
}

func (c *SCTPConn) SCTPRead(b []byte) (int, *SndRcvInfo, error) {
	return 0, nil, ErrUnsupported
}

// SyscallConn is declared here so that code holding a *SCTPConn or
// *SCTPListener still compiles when cross-compiled for a platform without SCTP.
// Without it the linux build has a method the others do not, and a caller who
// reaches for readiness handling — which is exactly what SyscallConn is for —
// fails to build rather than failing at run time with the reason.
func (c *SCTPConn) SyscallConn() (syscall.RawConn, error) {
	return nil, ErrUnsupported
}

func (ln *SCTPListener) SyscallConn() (syscall.RawConn, error) {
	return nil, ErrUnsupported
}

func (c *SCTPConn) SCTPReadFlags(b []byte) (int, *SndRcvInfo, int, error) {
	return 0, nil, 0, ErrUnsupported
}

func (c *SCTPConn) ReadMsg(max int) ([]byte, *SndRcvInfo, error) {
	return nil, nil, ErrUnsupported
}

func (c *SCTPConn) Close() error {
	return ErrUnsupported
}

func (c *SCTPConn) Abort() error {
	return ErrUnsupported
}

func (c *SCTPConn) CloseWithTimeout(timeout time.Duration) error {
	return ErrUnsupported
}

func (c *SCTPConn) SetWriteBuffer(bytes int) error {
	return ErrUnsupported
}

func (c *SCTPConn) GetWriteBuffer() (int, error) {
	return 0, ErrUnsupported
}

func (c *SCTPConn) SetReadBuffer(bytes int) error {
	return ErrUnsupported
}

func (c *SCTPConn) GetReadBuffer() (int, error) {
	return 0, ErrUnsupported
}

func ListenSCTP(net string, laddr *SCTPAddr) (*SCTPListener, error) {
	return nil, ErrUnsupported
}

func ListenSCTPExt(net string, laddr *SCTPAddr, options InitMsg) (*SCTPListener, error) {
	return nil, ErrUnsupported
}

func listenSCTPExtConfig(network string, laddr *SCTPAddr, options InitMsg, control func(network string, address string, c syscall.RawConn) error, handler NotificationHandler) (*SCTPListener, error) {
	return nil, ErrUnsupported
}

func FileListener(file *os.File) (*SCTPListener, error) {
	return nil, ErrUnsupported
}

func (ln *SCTPListener) Accept() (net.Conn, error) {
	return nil, ErrUnsupported
}

func (ln *SCTPListener) AcceptSCTP() (*SCTPConn, error) {
	return nil, ErrUnsupported
}

func (ln *SCTPListener) Close() error {
	return ErrUnsupported
}

func DialSCTP(net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

func DialSCTPExt(network string, laddr, raddr *SCTPAddr, options InitMsg) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

func dialSCTPExtConfig(network string, laddr, raddr *SCTPAddr, options InitMsg, control func(network string, address string, c syscall.RawConn) error, handler NotificationHandler) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

func DialSCTPContext(ctx context.Context, network string, laddr, raddr *SCTPAddr, options InitMsg) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

func dialSCTPExtConfigContext(ctx context.Context, network string, laddr, raddr *SCTPAddr, options InitMsg, control func(network string, address string, c syscall.RawConn) error, handler NotificationHandler) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

// isNonblocking is declared here because its caller, isEstablishedAssoc, is in
// sctp.go and so is built for every platform, while the real implementation
// needs syscall.SYS_FCNTL — which the syscall package does not define on
// Windows. Without this the package stopped compiling there, which defeats the
// point of this file: a caller cross-compiling for a platform without SCTP
// should get ErrUnsupported at run time, not a build failure.
//
// The value is unreachable in practice. Every connect path here returns
// ErrUnsupported from the getsockopt stub above, so isEstablishedAssoc never
// sees the EISCONN or EALREADY that would make it ask. True is nonetheless the
// answer that matches the documented conservative default.
func isNonblocking(fd int) bool {
	return true
}

// PeelOff is Linux-only for the same reason as the rest of this file, and
// additionally because it names syscall.SOCK_CLOEXEC, which the syscall package
// does not define everywhere. Keeping it in the shared file is what broke the
// Windows build once already.
func (c *SCTPConn) PeelOff(id int) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

func (c *SCTPConn) SCTPReadNextInfo(b []byte) (int, *SndRcvInfo, *NxtInfo, int, error) {
	return 0, nil, nil, 0, ErrUnsupported
}
