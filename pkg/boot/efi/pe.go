package efi

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"unsafe"

	"github.com/u-root/u-root/pkg/boot/kexec"
	"github.com/u-root/u-root/pkg/uio"
)

// sectionFlags describes the characteristics of each section.
type sectionFlags uint32

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
var (
	_IMAGE_SCN_MEM_DISCARDABLE sectionFlags = 0x02000000
	_IMAGE_SCN_MEM_EXECUTE     sectionFlags = 0x20000000
	_IMAGE_SCN_MEM_READ        sectionFlags = 0x40000000
	_IMAGE_SCN_MEM_WRITE       sectionFlags = 0x80000000
)

// machineType is the architecture target of the binary.
type machineType uint16

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
var (
	// amd64/x86-64.
	_IMAGE_FILE_MACHINE_AMD64 machineType = 0x8664

	// ARM64 little-endian.
	_IMAGE_FILE_MACHINE_ARM64 machineType = 0xaa64
)

const m16 = 0x1000000

// relocType is a PE image relocation within a .reloc section.
//
// (To be distinguished from a COFF relocation.)
type relocType uint8

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
const (
	// "The base relocation is skipped. This type can be used to pad a block."
	_IMAGE_REL_BASED_ABSOLUTE relocType = 0

	// "The base relocation applies the difference to the 64-bit field at offset."
	_IMAGE_REL_BASED_DIR64 relocType = 10
)

// Load implements OSImage.Load.
func Segments(kernel io.ReaderAt) (kexec.Segments, uintptr, error) {
	f, err := pe.NewFile(kernel)
	if err != nil {
		return nil, 0, err
	}
	kernelBuf, err := uio.ReadAll(kernel)
	if err != nil {
		return nil, 0, err
	}

	if machineType(f.Machine) != _IMAGE_FILE_MACHINE_AMD64 {
		return nil, 0, fmt.Errorf("EFI loader does not support arch %#x", f.Machine)
	}
	log.Printf("file characteristics: %#x", f.Characteristics)

	var (
		entry     uintptr
		imageBase uint64
	)
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return nil, 0, fmt.Errorf("32bit unsupported")

	case *pe.OptionalHeader64:
		entry = uintptr(oh.AddressOfEntryPoint)
		imageBase = oh.ImageBase

		log.Printf("base of code: %#x", oh.BaseOfCode)
		log.Printf("image base: %#x", oh.ImageBase)
	}

	var chosenBase uintptr
	if imageBase == 0 {
		// In qemu, on Linux, this physical address usually _HAPPENS_
		// to be free.
		//
		// TODO: move EFI kexec to a /dev, add ioctl for asking for an
		// allocation.
		chosenBase = 0x10000000
	} else {
		// Add 0x1000 just to make sure relocations are working.
		chosenBase = uintptr(imageBase) + 0x1000
	}

	log.Printf("entry: %#x", entry)

	// A note on terminology: the PE image format calls the target
	// address of each section the "virtual address" and the length the
	// "virtual size". Relocations refer to "page RVA" (relative virtual
	// address).
	//
	// In kexec, virtual target address == physical target address, so we
	// refer to the target address as the physical address as well.
	var segment kexec.Segments

	// Windows loader expects to also fing the header of the EFI file.
	// We add everything before the first section as the first segment.
	var section_0 = f.Sections[0]
	s := kexec.Segment{
		Buf: kexec.Range{
			Start: uintptr(unsafe.Pointer(&kernelBuf[0])),
			Size:  uint(section_0.Offset),
		},
		Phys: kexec.Range{
			Start: chosenBase,
			Size:  uint(uint64(section_0.VirtualAddress)),
		},
	}
	segment = append(segment, s)

	var reloc *pe.Section

	// Now add the actual sections.
	for _, section := range f.Sections {
		if section.Name == ".reloc" {
			reloc = section
		}
		// "The section can be discarded as needed." (usually .reloc)
		if sectionFlags(section.Characteristics)&_IMAGE_SCN_MEM_DISCARDABLE != 0 {
			continue
		}
		s := kexec.Segment{
			Buf: kexec.Range{
				Start: uintptr(unsafe.Pointer(&kernelBuf[section.Offset])),
				Size:  uint(section.Size),
			},
			Phys: kexec.Range{
				Start: chosenBase + uintptr(section.VirtualAddress),
				Size:  uint(section.VirtualSize),
			},
		}
		segment = append(segment, s)

		log.Printf("%s (%s - virtual range %s)", s, section.Name, kexec.Range{Start: uintptr(section.VirtualAddress), Size: uint(section.VirtualSize)})
	}

	// Note that there is a difference between COFF relocations and PE
	// image relocations.
	//
	// COFF relocations are per-section and in the parsed section.Relocs in
	// the debug/pe Go API.
	//
	// PE image relocations are in a section named ".reloc" and must be
	// manually parsed.
	if reloc != nil {
		log.Printf("reloc: %s", reloc)

		log.Printf("reloc: size %d virtualsize %d", reloc.Size, reloc.VirtualSize)
		r := reloc.Open()

		for {
			var hdr relocationChunkHeader
			if err := binary.Read(r, binary.LittleEndian, &hdr); err == io.EOF {
				break
			} else if err != nil {
				return nil, 0, err
			}

			log.Printf("pageRVA: %#x, totalsize: %d", hdr.PageRVA, hdr.TotalSize)
			if hdr.TotalSize == 0 {
				break
			}

			relocs := make([]uint16, (hdr.TotalSize-uint32(unsafe.Sizeof(hdr)))/2)
			if err := binary.Read(r, binary.LittleEndian, relocs); err == io.EOF {
				return nil, 0, fmt.Errorf("wrong number of elements %d for total size %d", len(relocs), hdr.TotalSize)
			} else if err != nil {
				return nil, 0, err
			}

			diff := int64(chosenBase) - int64(imageBase)

			for _, relo := range relocs {
				// Every relocation is 16 bits.
				//
				// 4 bits relocation type
				// 12 bits offset
				typ := relocType(relo & 0xf000 >> 12)
				offset := relo & 0xfff

				switch typ {
				case _IMAGE_REL_BASED_DIR64:
					imageOffset := hdr.PageRVA + uint32(offset)

					buf := segment.GetPhys(kexec.Range{Start: chosenBase + uintptr(imageOffset), Size: 8})
					if buf == nil || len(buf) < 8 {
						return nil, 0, fmt.Errorf("relocation at address %#x could not be found in image", imageOffset)
					}

					value := int64(binary.LittleEndian.Uint64(buf))
					binary.LittleEndian.PutUint64(buf, uint64(value+diff))

				case _IMAGE_REL_BASED_ABSOLUTE:
					// "relocation is skipped."
					continue

				default:
					return nil, 0, fmt.Errorf("relocation of type %d not implemented", typ)
				}
			}
		}
	}

	return segment, chosenBase + entry, nil
}

type relocationChunkHeader struct {
	PageRVA   uint32
	TotalSize uint32
}
