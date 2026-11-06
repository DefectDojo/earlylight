package repo

import (
	"fmt"
	"regexp"
	"strings"
)

// Build systems that make musl firmware: Buildroot and OpenWrt
// configurations name the package and the C library in one file; Yocto's
// TCLIBC and image contents are joined across the tree in finishBuild.

var (
	brOpenSSH     = regexp.MustCompile(`(?m)^BR2_PACKAGE_OPENSSH=y`)
	brServer      = regexp.MustCompile(`(?m)^BR2_PACKAGE_OPENSSH_SERVER=(y|n)|^# BR2_PACKAGE_OPENSSH_SERVER is not set`)
	brMusl        = regexp.MustCompile(`(?m)^BR2_TOOLCHAIN_(USES_MUSL|BUILDROOT_MUSL|EXTERNAL_[A-Z0-9_]*MUSL[A-Z0-9_]*)=y`)
	brLibc        = regexp.MustCompile(`(?m)^BR2_TOOLCHAIN_(USES_GLIBC|USES_UCLIBC|BUILDROOT_GLIBC|BUILDROOT_UCLIBC)=y`)
	brPAM         = regexp.MustCompile(`(?m)^BR2_PACKAGE_LINUX_PAM=y`)
	owrtServer    = regexp.MustCompile(`(?m)^CONFIG_PACKAGE_(openssh-server(?:-pam)?)=[ym]`)
	yoctoMusl     = regexp.MustCompile(`(?m)^\s*TCLIBC\s*\??\??=\s*["']musl["']`)
	yoctoOpenSSH  = regexp.MustCompile(`(?m)^[^#\n]*(IMAGE_INSTALL|IMAGE_FEATURES|EXTRA_IMAGE_FEATURES|CORE_IMAGE_EXTRA_INSTALL|RDEPENDS)[^=\n]*=[^\n]*\b(openssh-sshd|openssh|ssh-server-openssh|packagegroup-core-ssh-openssh)\b`)
	yoctoSSHGuard = regexp.MustCompile(`(?m)^[^#\n]*\bssh-server-dropbear\b`)
)

func lineOf(text string, at int) int { return strings.Count(text[:at], "\n") + 1 }

func (s *scanner) build(rel, text string) {
	switch {
	case brOpenSSH.MatchString(text):
		loc := brOpenSSH.FindStringIndex(text)
		if m := brServer.FindStringSubmatch(text); m != nil && m[1] != "y" {
			return // the client only
		}
		pam := ""
		if brPAM.MatchString(text) {
			pam = " It is built with PAM; setting UsePAM yes in sshd_config also closes the hole."
		}
		f := Finding{Rule: RuleBuild, File: rel, Line: lineOf(text, loc[0]), Props: map[string]string{"system": "buildroot"},
			Fix: "Buildroot master moved OpenSSH to 10.6p2 on 2026-11-05; the 2025.02.x to 2026.08.x branches had not when this was written. Move to a Buildroot with it, or add upstream commit 4353fdc43 as a patch under BR2_GLOBAL_PATCH_DIR/openssh/." + pam}
		switch {
		case brMusl.MatchString(text):
			f.Level = "error"
			f.Message = "Buildroot configuration builds the OpenSSH server against musl; Buildroot releases before 10.6p2 lack the *sshole fix"
		case brLibc.MatchString(text):
			return
		default:
			f.Rule, f.Level = RuleNotChecked, "note"
			f.Message = "Buildroot configuration builds the OpenSSH server, but its C library is not set in this file; with musl, Buildroot releases before 10.6p2 lack the *sshole fix"
		}
		s.addBuild(f)
	case owrtServer.MatchString(text):
		for _, m := range owrtServer.FindAllStringSubmatchIndex(text, -1) {
			pkg := text[m[2]:m[3]]
			s.addBuild(Finding{Rule: RuleBuild, File: rel, Line: lineOf(text, m[0]), Level: "error", Props: map[string]string{"system": "openwrt", "package": pkg},
				Message: fmt.Sprintf("OpenWrt configuration builds %s (OpenWrt uses musl); its openssh needs the *sshole fix", pkg),
				Fix:     "Build from an OpenWrt packages feed with the fix: 23.05 9.8p1-2, 24.10 9.9_p2-2, 25.12 and master 10.6_p2-1 (2026-11-05). 22.03 and older have none: move to a supported release, or add upstream commit 4353fdc43 to net/openssh/patches."})
		}
	default:
		if m := yoctoMusl.FindStringIndex(text); m != nil {
			s.yoctoMusl = append(s.yoctoMusl, Finding{File: rel, Line: lineOf(text, m[0])})
		}
		for _, m := range yoctoOpenSSH.FindAllStringIndex(text, -1) {
			s.yoctoSSH = append(s.yoctoSSH, Finding{File: rel, Line: lineOf(text, m[0])})
		}
	}
}

// pending build findings, returned by finishBuild.
func (s *scanner) addBuild(f Finding) { s.yoctoSSH = append(s.yoctoSSH, f) }

// finishBuild returns the build-system findings: Buildroot and OpenWrt as
// found, and Yocto images with OpenSSH where the tree sets TCLIBC to musl.
func (s *scanner) finishBuild() []Finding {
	var out []Finding
	for _, f := range s.yoctoSSH {
		if f.Rule != "" {
			out = append(out, f)
			continue
		}
		if len(s.yoctoMusl) == 0 {
			continue
		}
		m := s.yoctoMusl[0]
		out = append(out, Finding{Rule: RuleBuild, File: f.File, Line: f.Line, Level: "error", Props: map[string]string{"system": "yocto", "tclibc": fmt.Sprintf("%s:%d", m.File, m.Line)},
			Message: fmt.Sprintf("Yocto image installs the OpenSSH server and %s:%d sets TCLIBC to musl; OpenEmbedded's openssh before 10.6p2 lacks the *sshole fix", m.File, m.Line),
			Fix:     "OpenEmbedded-Core had OpenSSH 10.6p1 when this was written (2026-11-05). Add upstream commit 4353fdc43 as a patch in an openssh .bbappend (SRC_URI += \"file://avoid-password-authn-bypass.patch\"), or set PasswordAuthentication no."})
	}
	s.yoctoSSH, s.yoctoMusl = nil, nil
	return out
}

var _ = yoctoSSHGuard
