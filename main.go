package main

import (
	"bytes"
	"encoding/csv"
	"encoding/gob"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jsign/verkle-chunking-analysis/analysis"
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
	csvWriter.Write([]string{"tx", "pc_count", "chunk_count", "gas"})

	// Splice dirEntries into runtime.NumCPU() slices
	numProcessors := runtime.NumCPU()
	sliceSize := len(dirEntries) / numProcessors
	processorResults := make(chan processorResult)
	for i := 0; i < numProcessors; i++ {
		if i == numProcessors-1 {
			go processFiles(dirEntries[i*sliceSize:], processorResults)
		} else {
			go processFiles(dirEntries[i*sliceSize:(i+1)*sliceSize], processorResults)
		}
	}
	for i := 0; i < numProcessors; i++ {
		result := <-processorResults
		for _, txExecLength := range result.txExecutionLength {
			csvWriter.Write([]string{txExecLength.tx, fmt.Sprintf("%d", txExecLength.length), fmt.Sprintf("%d", result.report.NumCodeChunks), fmt.Sprintf("%d", result.report.Gas)})
		}
	}
}

type txExecLength struct {
	tx     string
	length int
}
type processorResult struct {
	txExecutionLength []txExecLength
	report            analysis.Report
}

func processFiles(dirEntries []os.DirEntry, out chan<- processorResult) {
	var ret processorResult

	for i, dirEntry := range dirEntries {
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
		ret.txExecutionLength = append(ret.txExecutionLength, txExecLength{tx: dirEntry.Name(), length: traceLength})

		chunker := z31bytechunker.New()
		for contractAddr, pcs := range pcTrace.Contracts {
			for _, pc := range pcs.PCs {
				chunker.AccessPC(contractAddr, pc)
			}
		}
		ret.report = chunker.GetReport()

		if i%10_000 == 0 {
			fmt.Printf("%.2f%%\n", float64(i)/float64(len(dirEntries))*100)
		}
	}
	out <- ret
}
