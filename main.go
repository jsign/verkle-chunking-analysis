package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jsign/verkle-chunking-analysis/analysis/z31bytechunker"
)

type contractTrace struct {
	Code []byte
	PCs  []uint64
}

type PCTrace struct {
	Contracts map[common.Address]contractTrace
}

func main() {
	dirEntries, err := os.ReadDir("pctrace")
	if err != nil {
		log.Fatal(err)
	}
	for _, dirEntry := range dirEntries {
		pcTraceBytes, err := os.ReadFile("pctrace/" + dirEntry.Name())
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewReader(pcTraceBytes)
		var pcTrace PCTrace
		if err := gob.NewDecoder(buf).Decode(&pcTrace); err != nil {
			log.Fatal(err)
		}

		chunker := z31bytechunker.New()
		for contractAddr, pcs := range pcTrace.Contracts {
			for _, pc := range pcs.PCs {
				chunker.AccessPC(contractAddr, pc)
			}
		}

		report := chunker.GetReport()
		if report.NumCodeChunks > 10 {
			fmt.Printf("%s: %d\n", dirEntry.Name(), report.NumCodeChunks)
		}
	}
}
