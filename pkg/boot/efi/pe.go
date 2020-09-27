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

const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000

const M16 = 0x1000000

type reloType uint8

const (
	IMAGE_REL_BASED_DIR64 reloType = 10
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

	log.Printf("kernelbuf: %d", len(kernelBuf))

	var (
		entry     uintptr
		imageBase uint64
	)
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return nil, 0, fmt.Errorf("32bit unsupported")

	case *pe.OptionalHeader64:
		entry = uintptr(oh.AddressOfEntryPoint)
		log.Printf("base of code: %#x", oh.BaseOfCode)
		log.Printf("image base: %#x", oh.ImageBase)
		imageBase = oh.ImageBase
	}

	//chosenBase := uintptr(0x100000000)
	chosenBase := uintptr(imageBase)

	log.Printf("entry: %#x", entry)

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
	log.Printf("virt: %#x + %#x | phys: %#x + %#x", s.Buf.Start, s.Buf.Size, s.Phys.Start, s.Phys.Size)
	segment = append(segment, s)

	var reloc *pe.Section
	// Now add the actuall sections
	for _, section := range f.Sections {
		if section.Name == ".reloc" {
			reloc = section
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
		log.Printf("virt: %#x + %#x | phys: %#x + %#x (%s)", s.Buf.Start, s.Buf.Size, s.Phys.Start, s.Phys.Size, section.Name)
		segment = append(segment, s)
	}

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

			relocs := make([]uint16, (hdr.TotalSize-8)/2)
			if err := binary.Read(r, binary.LittleEndian, relocs); err == io.EOF {
				return nil, 0, fmt.Errorf("wrong number of elements %d for total size %d", len(relocs), hdr.TotalSize)
			} else if err != nil {
				return nil, 0, err
			}

			diff := int64(chosenBase) - int64(imageBase)

			for _, relo := range relocs {
				// 4 bits relocation type. 12 bits offset.
				reloT := reloType(relo & 0xf000 >> 12)
				offset := relo & 0xfff

				switch reloT {
				case IMAGE_REL_BASED_DIR64:
					imageOffset := hdr.PageRVA + uint32(offset)

					value := int64(binary.LittleEndian.Uint64(kernelBuf[imageOffset:]))
					value += diff

					binary.LittleEndian.PutUint64(kernelBuf[imageOffset:], uint64(value))

				case 0:
					continue

				default:
					return nil, 0, fmt.Errorf("relocation of type % not implemented", reloT)
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
