// Copyright 2018-2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package multiboot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/u-root/u-root/pkg/boot/kexec"
	"github.com/u-root/u-root/pkg/ubinary"
	"github.com/u-root/u-root/pkg/uio"
)

// A module represents a module to be loaded along with the kernel.
type module struct {
	// Start is the inclusive start of the Module memory location
	Start uint32

	// End is the exclusive end of the Module memory location.
	End uint32

	// CmdLine is a pointer to a null-terminated ASCII string.
	CmdLine uint32

	// Reserved is always zero.
	Reserved uint32
}

type modules []module

// loadModules loads module files.
// Returns loaded modules description and buffer storing loaded modules.
// Memory layout of the loaded modules is following:
//			extraData_1
//			extraData_2
//			...
//			cmdLine_1
//			cmdLine_2
//			...
//			cmdLine_n
//			<padding>
//			modules_1
//			<padding>
//			modules_2
//			...
//			<padding>
//			modules_n
//
// <padding> aligns the start of each module to a page beginning.
func loadModulesAndStrings(mem *kexec.Memory, modules []Module, extraData ...string) ([]uintptr, modules, error) {
	var buf bytes.Buffer
	var extraPtrs []uintptr
	for _, d := range extraData {
		extraPtrs = append(extraPtrs, uintptr(buf.Len()))
		buf.WriteString(d)
		buf.WriteByte(0)
	}

	loaded, err := loadModules(&buf, modules)
	if err != nil {
		return nil, nil, err
	}

	cmdlineRange, err := mem.AddKexecSegment(buf.Bytes())
	if err != nil {
		return nil, nil, err
	}

	// Fix up module addresses and addresses for extraData.
	for i := range extraPtrs {
		extraPtrs[i] += uintptr(cmdlineRange.Start)
	}
	loaded.fix(uint32(cmdlineRange.Start))

	for i, mod := range loaded {
		log.Printf("Added module %s at [%#x, %#x)", modules[i].Name, mod.Start, mod.End)
	}
	return extraPtrs, loaded, nil
}

func loadModules(buf *bytes.Buffer, rmods []Module) (loaded modules, err error) {
	loaded = make(modules, len(rmods))

	for i, rmod := range rmods {
		if err := loaded[i].setCmdLine(buf, rmod.CmdLine); err != nil {
			return nil, err
		}
	}

	for i, rmod := range rmods {
		if err := loaded[i].loadModule(buf, rmod.Module, rmod.Name); err != nil {
			return nil, fmt.Errorf("error adding module %v: %v", rmod.Name, err)
		}
	}
	return loaded, nil
}

func pageAlign(val uint32) uint32 {
	mask := uint32(os.Getpagesize() - 1)
	return (val + mask) &^ mask
}

// pageAlignBuf pads buf to a page boundary.
func pageAlignBuf(buf *bytes.Buffer) error {
	mask := (os.Getpagesize() - 1)
	size := (buf.Len() + mask) &^ mask
	_, err := buf.Write(bytes.Repeat([]byte{0}, size-buf.Len()))
	return err
}

func (m *module) loadModule(buf *bytes.Buffer, r io.ReaderAt, name string) error {
	// place start of each module to a beginning of a page.
	if err := pageAlignBuf(buf); err != nil {
		return err
	}

	m.Start = uint32(buf.Len())

	if _, err := io.Copy(buf, uio.Reader(r)); err != nil {
		return err
	}

	m.End = uint32(buf.Len())
	return nil
}

func (m *module) setCmdLine(buf *bytes.Buffer, cmdLine string) error {
	m.CmdLine = uint32(buf.Len())
	if _, err := buf.WriteString(cmdLine); err != nil {
		return err
	}
	return buf.WriteByte(0)
}

// fix fixes pointers converting relative values to absolute values.
func (m modules) fix(base uint32) {
	for i := range m {
		m[i].Start += base
		m[i].End += base
		m[i].CmdLine += base
	}
}

// marshal writes out the module list in multiboot info format, as described in
// https://www.gnu.org/software/grub/manual/multiboot/multiboot.html#Boot-information-format
func (m modules) marshal() ([]byte, error) {
	buf := bytes.Buffer{}
	err := binary.Write(&buf, ubinary.NativeEndian, m)
	return buf.Bytes(), err
}

// elems adds mutiboot info elements describing where to find each module and
// its cmdline.
func (m modules) elems() []elem {
	var e []elem
	for _, mm := range m {
		e = append(e, &mutibootModule{
			cmdline:    uint64(mm.CmdLine),
			moduleSize: uint64(mm.End - mm.Start),
			ranges: []mutibootModuleRange{
				{
					startPageNum: uint64(mm.Start / uint32(os.Getpagesize())),
					numPages:     pageAlign(mm.End-mm.Start) / uint32(os.Getpagesize()),
				},
			},
		})
	}
	return e
}
