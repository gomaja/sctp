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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// crossCompileTargets are the platforms this package promises to compile for.
//
// The promise is the reason sctp_unsupported.go exists: a program that imports
// this package and is built for a platform without SCTP should get
// ErrUnsupported when it calls something, not a compiler error when it builds.
// A build failure is worse than a run-time error, because it cannot be handled
// and it breaks consumers who never call into SCTP on that platform at all.
//
// The list is one target per axis rather than every target Go supports,
// because each one costs a full compile of the standard library for that
// platform and the axes are what actually break: which syscall package the
// target has, its word size, and its byte order. Adding linux/ppc64le next to
// linux/amd64 costs twenty seconds and tests nothing new.
var crossCompileTargets = []struct{ goos, goarch, why string }{
	{"linux", "amd64", "the primary target"},
	{"linux", "arm64", "the other 64-bit target in normal use"},
	{"linux", "arm", "32-bit little-endian: catches atomic alignment mistakes"},
	{"linux", "386", "the linux && !386 tag boundary, where the stubs take over"},
	{"linux", "s390x", "64-bit big-endian, and the only arch getsockopt special-cases"},
	{"linux", "mips", "32-bit big-endian: both axes wrong at once"},

	{"darwin", "arm64", "the machine this is developed on"},
	{"darwin", "amd64", "Intel Macs"},
	{"windows", "amd64", "where the break this test exists for showed up"},
	{"windows", "386", "32-bit Windows, whose syscall package differs again"},
	{"freebsd", "amd64", "a BSD, with its own syscall package"},
	{"aix", "ppc64", "the most divergent syscall package Go ships"},
}

// TestCrossCompiles builds the package for every platform it claims to support.
//
// This exists because the claim was broken and nothing noticed. Two helpers
// were added to sctp.go, which carries no build tag and is therefore compiled
// everywhere: isNonblocking, which calls syscall.SYS_FCNTL, and applyTimeout,
// which calls syscall.SetsockoptTimeval. Neither is portable — SYS_FCNTL is
// absent from the syscall package on Windows, and SetsockoptTimeval takes a
// syscall.Handle there rather than an int. The package stopped building for
// windows/*, which it had built for before, and the whole suite stayed green
// because the suite only ever runs on one platform at a time.
//
// staticcheck did report the symptom: run under GOOS=darwin, it flags a handful
// of sctp.go functions as unused, because their only callers are in the
// linux-tagged file. But it reports several such functions that are perfectly
// portable too, so the signal was indistinguishable from the noise. The
// detector for "does it build on platform X" is building it for platform X.
//
// js/wasm, wasip1/wasm and plan9/* are deliberately absent. Their syscall
// packages define neither RawSockaddrInet4 nor AF_INET, which SCTPAddr's
// exported encoding needs, and no version of this package has ever built for
// them. Supporting them would mean moving exported API behind a build tag,
// which is a larger promise than the one made here.
func TestCrossCompiles(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiling every target takes longer than a unit test")
	}

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go tool on PATH: %v", err)
	}

	// A shared output path is fine because nothing reads it back; the build
	// either type-checks and links or it does not.
	outDir := t.TempDir()

	for _, target := range crossCompileTargets {
		// Copied because go.mod declares go 1.12, so the loop variable is
		// shared across iterations and the parallel subtests below would all
		// read whichever target the loop finished on.
		target := target

		t.Run(target.goos+"_"+target.goarch, func(t *testing.T) {
			t.Parallel()

			out := filepath.Join(outDir, target.goos+"_"+target.goarch)
			cmd := exec.Command(goTool, "build", "-o", out, ".")

			// CGO_ENABLED is forced off because a cross-compile with cgo on
			// needs a cross toolchain the developer almost certainly does not
			// have, and this package uses no cgo.
			cmd.Env = append(os.Environ(),
				"GOOS="+target.goos,
				"GOARCH="+target.goarch,
				"CGO_ENABLED=0",
			)

			if combined, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("build for %s/%s (%s) failed: %v\n%s",
					target.goos, target.goarch, target.why, err,
					strings.TrimSpace(string(combined)))
			}
		})
	}
}
