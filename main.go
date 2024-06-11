package main

import (
	"bytes"
	"encoding/csv"
	"encoding/gob"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jsign/verkle-chunking-analysis/analysis/z31bytechunker"
)

type contractTrace struct {
	PCs []uint64
}

type PCTrace struct {
	Contracts map[common.Address]contractTrace
}

func main() {
	dirEntries, err := os.ReadDir("pctrace")
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.OpenFile("trace_lengths.csv", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	csvWriter := csv.NewWriter(f)
	defer csvWriter.Flush()
	csvWriter.Write([]string{"tx", "length"})

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

		var traceLength int
		for _, pcs := range pcTrace.Contracts {
			traceLength += len(pcs.PCs)
		}
		if err := csvWriter.Write([]string{dirEntry.Name(), fmt.Sprintf("%d", traceLength)}); err != nil {
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
