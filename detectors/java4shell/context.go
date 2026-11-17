package java4shell

import (
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/sys/cpu"
)

// CPU is the CPU this scan ran on, as context. The vulnerable decoder runs
// only on a CPU with AVX-512F, AVX-512BW, AVX-512 VBMI and BMI2, but a
// runtime that does not run it here can run it on another host (containers
// and virtual machines move), so a CPU without them clears nothing.
type CPU struct {
	Arch       string `json:"arch"`
	AVX512F    bool   `json:"avx512f"`
	AVX512BW   bool   `json:"avx512bw"`
	AVX512VBMI bool   `json:"avx512vbmi"`
	BMI2       bool   `json:"bmi2"`
	Affected   bool   `json:"runs_vulnerable_decoder"`
	Note       string `json:"note"`
}

// thisCPU reads the scanning machine's CPU features (CPUID, with the
// operating system's AVX-512 state support checked).
func thisCPU() (CPU, bool) {
	if runtime.GOARCH != "amd64" {
		return CPU{Arch: runtime.GOARCH, Note: "this scan ran on a CPU that is not x86-64; that says nothing about where the scanned runtimes run"}, true
	}
	c := CPU{Arch: "x86-64", AVX512F: cpu.X86.HasAVX512F, AVX512BW: cpu.X86.HasAVX512BW, AVX512VBMI: cpu.X86.HasAVX512VBMI, BMI2: cpu.X86.HasBMI2}
	c.Affected = c.AVX512F && c.AVX512BW && c.AVX512VBMI && c.BMI2
	if c.Affected {
		c.Note = "this CPU has AVX-512F, AVX-512BW, AVX-512 VBMI and BMI2: a vulnerable runtime started here generates the vulnerable decoder unless its options turn it off"
	} else {
		c.Note = "this CPU lacks at least one of AVX-512F, AVX-512BW, AVX-512 VBMI and BMI2, so a vulnerable runtime started here does not generate the vulnerable decoder; this is context only, not a clearance: the same runtime or image runs it on a host that has them"
	}
	return c, true
}

// crash is a HotSpot crash log (hs_err_pid*.log), as context: the Java
// version and CPU of a past crash, and whether the crashing frame was the
// Base64 decoder.
type crash struct {
	Path    string `json:"path"`
	Version string `json:"java_version,omitempty"`
	CPUVBMI bool   `json:"cpu_avx512vbmi"`
	Frame   string `json:"problematic_frame,omitempty"`
	Base64  bool   `json:"base64_decoder_frame"`
}

var (
	jreLine   = regexp.MustCompile(`(?m)^# JRE version: [^\n(]*\(([0-9][^)\s]{0,60})\)`)
	frameLine = regexp.MustCompile(`(?m)^# Problematic frame:\s*\n#\s*([^\n]{1,300})`)
	cpuLine   = regexp.MustCompile(`(?m)^CPU:[^\n]*`)
)

func readCrash(p string, b []byte) crash {
	c := crash{Path: p}
	if m := jreLine.FindSubmatch(b); m != nil {
		c.Version = string(m[1])
	}
	if m := frameLine.FindSubmatch(b); m != nil {
		c.Frame = strings.TrimSpace(string(m[1]))
		lf := strings.ToLower(c.Frame)
		c.Base64 = strings.Contains(lf, "base64") || strings.Contains(lf, "decodeblock")
	}
	if m := cpuLine.Find(b); m != nil {
		c.CPUVBMI = strings.Contains(string(m), "avx512_vbmi") || strings.Contains(string(m), "avx512vbmi")
	}
	return c
}
