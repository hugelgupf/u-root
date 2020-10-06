package efi

import (
	"debug/pe"
	"io"
	"log"
	"unsafe"

	"github.com/u-root/u-root/pkg/boot/kexec"
	"github.com/u-root/u-root/pkg/uio"
)

const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000

const M16 = 0x1000000

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
			Start: M16,
			Size:  uint(uint64(section_0.VirtualAddress)),
		},
	}
	log.Printf("virt: %#x + %#x | phys: %#x + %#x", s.Buf.Start, s.Buf.Size, s.Phys.Start, s.Phys.Size)
	segment = append(segment, s)

	// Now add the actuall sections
	for _, section := range f.Sections {
		s := kexec.Segment{
			Buf: kexec.Range{
				Start: uintptr(unsafe.Pointer(&kernelBuf[section.Offset])),
				Size:  uint(section.Size),
			},
			Phys: kexec.Range{
				Start: M16 + uintptr(section.VirtualAddress),
				Size:  uint(section.VirtualSize),
			},
		}
		log.Printf("virt: %#x + %#x | phys: %#x + %#x", s.Buf.Start, s.Buf.Size, s.Phys.Start, s.Phys.Size)
		segment = append(segment, s)
	}

	var entry uintptr
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entry = uintptr(oh.AddressOfEntryPoint)
	case *pe.OptionalHeader64:
		entry = uintptr(oh.AddressOfEntryPoint)
	}

	return segment, M16 + entry, nil
}
