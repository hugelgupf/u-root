package main

import (
	"debug/elf"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"os"
	"unsafe"
)

const vaddr = 0x400000

var hdrSize = unsafe.Sizeof(elf.Header64{})
var shdrSize = unsafe.Sizeof(elf.Section64{})
var phdrSize = unsafe.Sizeof(elf.Prog64{})

type payloader interface {
	payload() []byte
	setOffset(offset uint64)
}

type segment interface {
	payloader
	header(offset uint64) elf.Prog64
}

type section interface {
	name() string
	section() elf.Section64
}

type prog struct {
	typ     elf.ProgType
	content []byte
}

func (p *prog) payload() []byte {
	return p.content
}

func (p *prog) setOffset(offset uint64) {
}

func (p *prog) header(offset uint64) elf.Prog64 {
	return elf.Prog64{
		Type:   uint32(p.typ),
		Flags:  uint32(elf.PF_X | elf.PF_R | elf.PF_W),
		Align:  4096,
		Off:    offset,
		Vaddr:  uint64(vaddr) + offset,
		Filesz: uint64(len(p.content)),
		Memsz:  uint64(len(p.content)),
	}
}

type segmentSection struct {
	prog

	Name    string
	Type    elf.SectionType
	Flags   elf.SectionFlag
	Link    uint32
	Info    uint32
	Entsize uint64

	offset uint64
	vaddr  uint64
	size   uint64
}

func (p *segmentSection) name() string {
	return p.Name
}

func (p *segmentSection) header(offset uint64) elf.Prog64 {
	p.offset = offset
	p.vaddr = uint64(vaddr) + offset
	p.size = uint64(len(p.prog.content))
	return p.prog.header(offset)
}

func (p *segmentSection) section() elf.Section64 {
	return elf.Section64{
		Type:      uint32(p.Type),
		Flags:     uint64(p.Flags),
		Link:      p.Link,
		Info:      p.Info,
		Addr:      p.vaddr,
		Off:       p.offset,
		Size:      p.size,
		Addralign: 4096,
		Entsize:   p.Entsize,
	}
}

type section64 struct {
	elf.Section64

	Name string
}

func (s *section64) name() string {
	return s.Name
}

func (s *section64) section() elf.Section64 {
	return s.Section64
}

type strtab struct {
	content []byte

	offset uint64
	vaddr  uint64
}

func (s *strtab) name() string {
	return ".strtab"
}

func (s *strtab) addName(t string) uint32 {
	idx := uint32(len(s.content))
	s.content = append(s.content, t...)
	s.content = append(s.content, '\x00')
	return idx
}

func (s *strtab) payload() []byte {
	return s.content
}

func (s *strtab) setOffset(offset uint64) {
	s.offset = offset
	s.vaddr = uint64(vaddr) + offset
}

func (s *strtab) section() elf.Section64 {
	return elf.Section64{
		Name:      1,
		Type:      uint32(elf.SHT_STRTAB),
		Flags:     uint64(elf.SHF_WRITE | elf.SHF_ALLOC),
		Link:      0,
		Info:      0,
		Addr:      s.vaddr,
		Off:       s.offset,
		Size:      uint64(len(s.content)),
		Addralign: 4096,
		Entsize:   0,
	}
}

func writeHeader(w io.Writer, numPhdr, numSections int, sectionOffset uint64, strtabIndex uint16) error {
	var ident [elf.EI_NIDENT]byte
	copy(ident[:], elf.ELFMAG[:])
	ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	ident[elf.EI_OSABI] = byte(elf.ELFOSABI_NONE)
	ident[elf.EI_ABIVERSION] = 0

	return binary.Write(w, binary.LittleEndian, elf.Header64{
		Ident:     ident,
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Entry:     uint64(vaddr + hdrSize + phdrSize),
		Phoff:     uint64(hdrSize),
		Ehsize:    uint16(hdrSize),
		Phentsize: uint16(phdrSize),
		Phnum:     uint16(numPhdr),
		Shentsize: uint16(shdrSize),
		Shnum:     uint16(numSections),
		Shoff:     sectionOffset,
		Shstrndx:  strtabIndex,
	})
}

type file struct {
	p []segment
	s []section
}

func (f *file) write(w io.Writer) error {
	var sectionOffset uint64
	var numSections int
	var strtabIndex uint16
	var headers []elf.Section64
	var payloaders []payloader

	strtab := &strtab{}
	if len(f.s) > 0 {
		strtab.addName("")
		strtab.addName(".strtab")
		for _, s := range f.s {
			nameIdx := strtab.addName(s.name())
			shdr := s.section()
			shdr.Name = nameIdx
			headers = append(headers, shdr)
		}

		sectionOffset += uint64(hdrSize) + uint64(len(f.p))*uint64(phdrSize)
		for _, p := range f.p {
			sectionOffset += uint64(len(p.payload()))
		}
		sectionOffset += uint64(len(strtab.content))

		numSections = len(f.s) + 2
		strtabIndex = 1

		payloaders = append(payloaders, strtab)
	}

	if err := writeHeader(w, len(f.p), numSections, sectionOffset, strtabIndex); err != nil {
		return err
	}

	offset := uint64(0)
	for _, p := range f.p {
		phdr := p.header(uint64(hdrSize) + uint64(len(f.p))*uint64(phdrSize) + offset)
		offset += phdr.Filesz
		log.Printf("segment: %#v", phdr)
		if err := binary.Write(w, binary.LittleEndian, phdr); err != nil {
			return err
		}
		payloaders = append(payloaders, p)
	}

	offset = uint64(hdrSize) + uint64(len(f.p))*uint64(phdrSize)
	for _, p := range payloaders {
		p.setOffset(offset)
		b := p.payload()
		n, err := w.Write(b)
		if err != nil {
			return err
		} else if n != len(b) {
			return io.ErrUnexpectedEOF
		}
		offset += uint64(n)
	}

	if len(f.s) > 0 {
		// Section header entry 0 has to be this 0-filled thing, if sections exist.
		for _, s := range []section{&section64{}, strtab} {
			if err := binary.Write(w, binary.LittleEndian, s.section()); err != nil {
				return err
			}
		}
		for _, shdr := range headers {
			if err := binary.Write(w, binary.LittleEndian, shdr); err != nil {
				return err
			}
		}
	}
	return nil
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatalf("Must have 1 arg")
	}
	path := flag.Arg(0)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0777)
	if err != nil {
		log.Fatal(err)
	}
	dynamic := &segmentSection{
		Name: ".dynamic",
		prog: prog{
			typ:     elf.PT_DYNAMIC,
			content: []byte{0x01},
		},
		Type:    elf.SHT_DYNAMIC,
		Flags:   elf.SHF_WRITE | elf.SHF_ALLOC,
		Link:    1,
		Info:    0,
		Entsize: 10,
	}
	exec := &file{
		p: []segment{
			&prog{
				typ: elf.PT_LOAD,
				// pushq $60+pop rax is 3 bytes, movl eax,$60 is 5 bytes.
				content: []byte{
					0x6a, 60, // push 60 (exit syscall)
					0x58,       // pop rax
					0x31, 0xff, // xor edi,edi
					0x0f, 0x05, // syscall
				},
			},
			dynamic,
		},
		s: []section{
			dynamic,
		},
	}
	if err := exec.write(f); err != nil {
		log.Fatal(err)
	}
}
