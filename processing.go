package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jsign/verkle-chunking-analysis/analysis"
	"github.com/jsign/verkle-chunking-analysis/analysis/z31bytechunker"
	"github.com/jsign/verkle-chunking-analysis/analysis/z32bytechunker"
)

type txExecLength struct {
	tx     string
	length int
}
type processorResult struct {
	txExecutionLength []txExecLength
	reports           []analysis.Report
}

func processFiles(contractBytecodes map[common.Address][]byte, pcTraces []string, out chan<- processorResult) {
	for i, pcTracePath := range pcTraces {
		var ret processorResult

		pcTraceBytes, err := os.ReadFile(pcTracePath)
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
		_, txHash := path.Split(pcTracePath)
		ret.txExecutionLength = append(ret.txExecutionLength, txExecLength{tx: txHash, length: traceLength})

		touchedContracts := make([]common.Address, 0, len(pcTrace.ContractTraces))
		for contractAddr := range pcTrace.ContractTraces {
			touchedContracts = append(touchedContracts, contractAddr)
		}

		// TODO: create interface and list of chunkers below.

		// 31-byte chunker
		z31ByteChunker := z31bytechunker.New(touchedContracts)
		for contractAddr, pcs := range pcTrace.ContractTraces {
			for _, pc := range pcs.PCs {
				z31ByteChunker.AccessPC(contractAddr, pc)
			}
		}
		ret.reports = append(ret.reports, z31ByteChunker.GetReport())

		// 32-byte chunker
		z32ByteChunker := z32bytechunker.New(touchedContracts, contractBytecodes)
		for contractAddr, pcs := range pcTrace.ContractTraces {
			for _, pc := range pcs.PCs {
				z32ByteChunker.AccessPC(contractAddr, pc)
			}
		}
		ret.reports = append(ret.reports, z31ByteChunker.GetReport())

		if i%5_000 == 0 {
			fmt.Printf("%.2f%%\n", float64(i)/float64(len(pcTraces))*100)
		}
		out <- ret
	}
}
