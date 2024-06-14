package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"path"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jsign/verkle-chunking-analysis/analysis"
	"github.com/jsign/verkle-chunking-analysis/analysis/z31bytechunker"
	"github.com/jsign/verkle-chunking-analysis/analysis/z32bytechunker"
)

type pcTraceResult struct {
	err error

	tx              string
	execLength      int
	chunkersMetrics []analysis.ChunkerMetrics
}

func processFiles(contractBytecodes map[common.Address][]byte, pcTraces []string, out chan<- pcTraceResult) {
	for _, pcTracePath := range pcTraces {
		pcTraceBytes, err := os.ReadFile(pcTracePath)
		if err != nil {
			out <- pcTraceResult{err: fmt.Errorf("error reading file: %w", err)}
			return
		}
		buf := bytes.NewReader(pcTraceBytes)
		var pcTrace PCTrace
		if err := gob.NewDecoder(buf).Decode(&pcTrace); err != nil {
			out <- pcTraceResult{err: fmt.Errorf("error decoding file: %w", err)}
			return
		}

		var traceLength int
		for _, pcs := range pcTrace.ContractTraces {
			traceLength += len(pcs.PCs)
		}
		_, txHash := path.Split(pcTracePath)
		res := pcTraceResult{tx: txHash, execLength: traceLength}

		touchedContracts := make([]common.Address, 0, len(pcTrace.ContractTraces))
		for contractAddr := range pcTrace.ContractTraces {
			touchedContracts = append(touchedContracts, contractAddr)
		}

		// TODO: create interface and list of chunkers below.

		// 31-byte chunker
		z31ByteChunker, err := z31bytechunker.New(touchedContracts, contractBytecodes)
		if err != nil {
			out <- pcTraceResult{err: fmt.Errorf("error creating z31ByteChunker: %w", err)}
			return
		}
		for contractAddr, pcs := range pcTrace.ContractTraces {
			for _, pc := range pcs.PCs {
				z31ByteChunker.AccessPC(contractAddr, pc)
			}
		}
		res.chunkersMetrics = append(res.chunkersMetrics, z31ByteChunker.GetReport())

		// 32-byte chunker
		z32ByteChunker, err := z32bytechunker.New(touchedContracts, contractBytecodes)
		if err != nil {
			out <- pcTraceResult{err: fmt.Errorf("error creating z31ByteChunker: %w", err)}
			return
		}
		for contractAddr, pcs := range pcTrace.ContractTraces {
			for _, pc := range pcs.PCs {
				z32ByteChunker.AccessPC(contractAddr, pc)
			}
		}
		res.chunkersMetrics = append(res.chunkersMetrics, z32ByteChunker.GetReport())
		out <- res
	}
}
