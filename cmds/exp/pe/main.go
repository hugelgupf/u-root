package main

import (
	"flag"
	"log"
	"os"

	"github.com/u-root/u-root/pkg/boot/efi"
)

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		log.Fatalf("expect only file name")
	}

	f, err := os.Open(args[0])
	if err != nil {
		log.Fatal(err)
	}

	if _, _, err := efi.Segments(f); err != nil {
		log.Fatalf("segment parsing failed: %v", err)
	}
}
