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

	tx               string
	execLength       int
	receiptGas       uint64
	to               common.Address
	numExecContracts int
	chunkersMetrics  []analysis.ChunkerMetrics
}

func processFiles(
	contractBytecodes map[common.Address][]byte,
	tracesPath []string,
	filterContractsChunksStats map[common.Address]struct{},
	out chan<- pcTraceResult) {
	chunkers := []analysis.Chunker{z31bytechunker.New(), z32bytechunker.New()}

	for _, pcTracePath := range tracesPath {
		pcTraceBytes, err := os.ReadFile(pcTracePath)
		if err != nil {
			out <- pcTraceResult{err: fmt.Errorf("error reading file: %w", err)}
			return
		}
		buf := bytes.NewReader(pcTraceBytes)
		var txOutput traceOutput
		if err := gob.NewDecoder(buf).Decode(&txOutput); err != nil {
			out <- pcTraceResult{err: fmt.Errorf("error decoding file: %w", err)}
			return
		}

		var traceLength int
		for _, pcs := range txOutput.ContractsPCs {
			traceLength += len(pcs)
		}
		_, txHash := path.Split(pcTracePath)
		res := pcTraceResult{
			tx:               txHash,
			to:               txOutput.To,
			execLength:       traceLength,
			receiptGas:       txOutput.ReceiptGas,
			numExecContracts: len(txOutput.ContractsPCs),
		}

		touchedContracts := make([]common.Address, 0, len(txOutput.ContractsPCs))
		for contractAddr := range txOutput.ContractsPCs {
			touchedContracts = append(touchedContracts, contractAddr)
		}

		_, enableChunksStats := filterContractsChunksStats[txOutput.To]
		for _, ch := range chunkers {
			if err := ch.Init(touchedContracts, contractBytecodes, enableChunksStats); err != nil {
				out <- pcTraceResult{err: fmt.Errorf("error creating chunker: %s", err)}
				return
			}
			for contractAddr, pcs := range txOutput.ContractsPCs {
				for _, pc := range pcs {
					if err := ch.AccessPC(contractAddr, pc); err != nil {
						out <- pcTraceResult{err: fmt.Errorf("error accessing pc: %s", err)}
						return
					}
				}
			}
			res.chunkersMetrics = append(res.chunkersMetrics, ch.GetReport())
		}

		out <- res
	}
}
