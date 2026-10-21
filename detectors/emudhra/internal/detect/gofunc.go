package detect

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
)

// goFuncTable returns a lookup over the Go function table (pclntab) of an ELF or
// Mach-O binary, so a function counts only if the binary really contains it, not
// merely its name somewhere in the data. ok is false when the table can't be read
// (PE binaries, unusual layouts); callers then fall back to a name search.
func goFuncTable(data []byte) (has func(name string) bool, ok bool) {
	pcln, text, ok := pclntab(data)
	if !ok {
		return nil, false
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(pcln, text))
	if err != nil {
		return nil, false
	}
	return func(name string) bool { return tab.LookupFunc(name) != nil }, true
}

func pclntab(data []byte) ([]byte, uint64, bool) {
	r := bytes.NewReader(data)
	if f, err := elf.NewFile(r); err == nil {
		defer f.Close()
		p, t := f.Section(".gopclntab"), f.Section(".text")
		if p == nil || t == nil {
			return nil, 0, false
		}
		b, err := p.Data()
		if err != nil {
			return nil, 0, false
		}
		return b, t.Addr, true
	}
	if f, err := macho.NewFile(r); err == nil {
		defer f.Close()
		return machoPclntab(f)
	}
	if ff, err := macho.NewFatFile(r); err == nil {
		defer ff.Close()
		if len(ff.Arches) > 0 {
			return machoPclntab(ff.Arches[0].File)
		}
	}
	return nil, 0, false
}

func machoPclntab(f *macho.File) ([]byte, uint64, bool) {
	p, t := f.Section("__gopclntab"), f.Section("__text")
	if p == nil || t == nil {
		return nil, 0, false
	}
	b, err := p.Data()
	if err != nil {
		return nil, 0, false
	}
	return b, t.Addr, true
}
