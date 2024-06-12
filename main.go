package main

import (
	"bytes"
	"encoding/csv"
	"encoding/gob"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jsign/verkle-chunking-analysis/analysis"
	"github.com/jsign/verkle-chunking-analysis/analysis/z31bytechunker"
)

var pcTraceFolder = "/data/pctrace"

type contractTrace struct {
	PCs []uint64
}

type PCTrace struct {
	ContractTraces map[common.Address]contractTrace
}

func main() {
	allDirEntries, err := os.ReadDir(pcTraceFolder)
	if err != nil {
		log.Fatal(err)
	}
	dirEntries := make([]os.DirEntry, 0, len(allDirEntries))
	for i, dirEntry := range allDirEntries {
		if dirEntry.IsDir() {
			continue
		}
		if i > 1_000_000 {
			break
		}
		dirEntries = append(dirEntries, dirEntry)
	}

	f, err := os.OpenFile("trace_lengths.csv", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	csvWriter := csv.NewWriter(f)
	defer csvWriter.Flush()
	csvWriter.Write([]string{"tx", "execution_length", "chunks_accessed", "chunk_gas"})

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
	for i := 0; i < len(dirEntries); i++ {
		result := <-processorResults
		for _, txExecLength := range result.txExecutionLength {
			csvWriter.Write([]string{txExecLength.tx[:10], fmt.Sprintf("%d", txExecLength.length), fmt.Sprintf("%d", result.report.NumCodeChunks), fmt.Sprintf("%d", result.report.Gas)})
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
	for i, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue
		}
		var ret processorResult

		pcTraceBytes, err := os.ReadFile(path.Join(pcTraceFolder, dirEntry.Name()))
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewReader(pcTraceBytes)
		var pcTrace PCTrace
		if err := gob.NewDecoder(buf).Decode(&pcTrace); err != nil {
			log.Fatal(err)
		}

		var traceLength int
		for _, pcs := range pcTrace.ContractTraces {
			traceLength += len(pcs.PCs)
		}
		ret.txExecutionLength = append(ret.txExecutionLength, txExecLength{tx: dirEntry.Name(), length: traceLength})

		touchedContracts := make([]common.Address, 0, len(pcTrace.ContractTraces))
		for contractAddr := range pcTrace.ContractTraces {
			touchedContracts = append(touchedContracts, contractAddr)
		}
		chunker := z31bytechunker.New(touchedContracts)
		for contractAddr, pcs := range pcTrace.ContractTraces {
			for _, pc := range pcs.PCs {
				chunker.AccessPC(contractAddr, pc)
			}
		}
		ret.report = chunker.GetReport()

		if i%5_000 == 0 {
			fmt.Printf("%.2f%%\n", float64(i)/float64(len(dirEntries))*100)
		}
		out <- ret
	}
}
