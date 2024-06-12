package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"

	"github.com/ethereum/go-ethereum/common"
)

var pcTraceFolder = "/data/pctrace"

type contractTrace struct {
	PCs []uint64
}

type PCTrace struct {
	ContractTraces map[common.Address]contractTrace
}

func main() {
	pcTracePaths, contractBytecodes, err := loadData(pcTraceFolder, 1_000_000)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.OpenFile("trace_lengths.csv", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	csvWriter := csv.NewWriter(f)
	defer csvWriter.Flush()
	// TODO: generalize
	csvWriter.Write([]string{"tx", "execution_length", "31bytechunker_gas", "32bytechunker_gas"})

	numProcessors := runtime.NumCPU()
	sliceSize := len(pcTracePaths) / numProcessors
	processorResults := make(chan processorResult)
	for i := 0; i < numProcessors; i++ {
		if i == numProcessors-1 {
			go processFiles(contractBytecodes, pcTracePaths[i*sliceSize:], processorResults)
		} else {
			go processFiles(contractBytecodes, pcTracePaths[i*sliceSize:(i+1)*sliceSize], processorResults)
		}
	}
	for i := 0; i < len(pcTracePaths); i++ {
		result := <-processorResults
		for _, txExecLength := range result.txExecutionLength {
			line := []string{txExecLength.tx[:10], fmt.Sprintf("%d", txExecLength.length)}
			for _, report := range result.reports {
				line = append(line, fmt.Sprintf("%d", report.Gas))
			}
			csvWriter.Write(line)
		}
	}
}

func loadData(folderPath string, limit int) ([]string, map[common.Address][]byte, error) {
	dirEntries, err := os.ReadDir(folderPath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read directory %s: %w", folderPath, err)
	}
	pcTracesPaths := make([]string, 0, len(dirEntries))
	for i, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue
		}
		if i >= limit {
			break
		}
		pcTracesPaths = append(pcTracesPaths, path.Join(folderPath, dirEntry.Name()))
	}

	dirEntries, err = os.ReadDir(path.Join(folderPath, "code"))
	if err != nil {
		return nil, nil, fmt.Errorf("could not read directory %s: %w", path.Join(folderPath, "code"), err)
	}
	contractBytecodes := map[common.Address][]byte{}
	for _, dirEntry := range dirEntries {
		bytecode, err := os.ReadFile(path.Join(folderPath, "code", dirEntry.Name()))
		if err != nil {
			return nil, nil, fmt.Errorf("could not read file %s: %w", path.Join(folderPath, dirEntry.Name()), err)
		}
		contractBytecodes[common.HexToAddress(dirEntry.Name())] = bytecode
	}

	return pcTracesPaths, contractBytecodes, nil
}
