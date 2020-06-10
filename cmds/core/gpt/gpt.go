// Copyright 2016-2017 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// gpt reads and writes GPT headers.
//
// Synopsis:
//     gpt [-w] file
//
// Description:
//     For -w, it reads a JSON formatted GPT from stdin, and writes 'file'
//     which is usually a device. It writes both primary and secondary headers.
//
//     Otherwise it just writes the headers to stdout in JSON format.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"github.com/u-root/u-root/pkg/gpt"
)

const cmd = "gpt [options] file"

var (
	write   = flag.Bool("w", false, "Write GPT to file")
	jsonOut = flag.Bool("json", true, "Write JSON output")
)

func init() {
	defUsage := flag.Usage
	flag.Usage = func() {
		os.Args[0] = cmd
		defUsage()
		os.Exit(1)
	}
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
	}

	m := os.O_RDONLY
	if *write {
		m = os.O_RDWR
	}

	n := flag.Args()[0]
	f, err := os.OpenFile(n, m, 0)
	if err != nil {
		log.Fatal(err)
	}

	switch *write {
	case true:
		var p = &gpt.PartitionTable{}
		if err := json.NewDecoder(os.Stdin).Decode(&p); err != nil {
			log.Fatalf("Reading in JSON: %v", err)
		}
		if err := gpt.Write(f, p); err != nil {
			log.Fatalf("Writing %v: %v", n, err)
		}
	default:
		// We might get one back, we might get both.
		// In the event of an error, we show what we can
		// so you can at least see what went wrong.
		p, err := gpt.New(f)
		if err != nil {
			log.Printf("Error reading %v: %v", n, err)
		}
		if *jsonOut {
			// Emit this as a JSON array. Suggestions welcome on better ways to do this.
			if _, err := fmt.Printf("%s\n", p); err != nil {
				log.Fatal(err)
			}
		} else {
			fmt.Printf("Sector size: %d\n\n", 512)

			writer := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)
			fmt.Fprintf(writer, "Number\tStart (sector)\tEnd (sector)\tType\tGUID\tName\n")
			for i, part := range p.GPT.Partitions {
				if !part.IsEmpty() {
					fmt.Fprintf(writer, "%d\t%d\t%d\t%s\t%s\t%s\n", i+1, part.FirstLBA, part.LastLBA, part.Type, part.Id, part.Name())
				}
			}
			writer.Flush()
		}

	}
}
