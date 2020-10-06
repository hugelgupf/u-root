package boot

import (
	"io"
	"os"

	"github.com/u-root/u-root/pkg/boot/efi"
	"github.com/u-root/u-root/pkg/boot/kexec"
	"github.com/u-root/u-root/pkg/uio"
)

// PEImage is a PE-formated OSImage.
type PEImage struct {
	Kernel io.ReaderAt
}

var _ OSImage = &PEImage{}

func (PEImage) Label() string {
	return "EFI Image"
}

func (PEImage) String() string {
	return "EFI Image"
}

func (PEImage) Edit(func(cmdline string) string) {}

func PEImageFromFile(kernel *os.File) (*PEImage, error) {
	k, err := uio.InMemFile(kernel)
	if err != nil {
		return nil, err
	}
	return &PEImage{
		Kernel: k,
	}, nil
}

const KEXEC_RUN_PE = 0x00000004

// Load implements OSImage.Load.
func (p *PEImage) Load(verbose bool) error {
	segments, entry, err := efi.Segments(p.Kernel)
	if err != nil {
		return err
	}

	return kexec.Load(entry, segments, KEXEC_RUN_PE)
}
