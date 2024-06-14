package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/sync/errgroup"
)

var pcTraceFolder = "/data/pctrace"

type contractTrace struct {
	PCs []uint64
}

type PCTrace struct {
	ContractTraces map[common.Address]contractTrace
}

func main() {
	pcTracePaths, contractBytecodes, err := loadData(pcTraceFolder, -1)
	if err != nil {
		log.Fatal(err)
	}

	numProcessors := runtime.NumCPU()
	sliceSize := len(pcTracePaths) / numProcessors
	processorResults := make(chan pcTraceResult)
	for i := 0; i < numProcessors; i++ {
		if i == numProcessors-1 {
			go processFiles(contractBytecodes, pcTracePaths[i*sliceSize:], processorResults)
		} else {
			go processFiles(contractBytecodes, pcTracePaths[i*sliceSize:(i+1)*sliceSize], processorResults)
		}
	}

	if err := outputResults(processorResults, len(pcTracePaths), contractBytecodes); err != nil {
		log.Fatal(err)
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
		if limit != -1 && i >= limit {
			break
		}
		pcTracesPaths = append(pcTracesPaths, path.Join(folderPath, dirEntry.Name()))
	}

	dirEntries, err = os.ReadDir(path.Join(folderPath, "code"))
	if err != nil {
		return nil, nil, fmt.Errorf("could not read directory %s: %w", path.Join(folderPath, "code"), err)
	}

	fmt.Printf("Loading contract bytecodes... ")
	var lock sync.Mutex
	group, _ := errgroup.WithContext(context.Background())
	group.SetLimit(runtime.NumCPU())
	contractBytecodes := map[common.Address][]byte{}
	for _, dirEntry := range dirEntries {
		dirEntry := dirEntry
		group.Go(func() error {
			bytecode, err := os.ReadFile(path.Join(folderPath, "code", dirEntry.Name()))
			if err != nil {
				return fmt.Errorf("could not read file %s: %w", path.Join(folderPath, dirEntry.Name()), err)
			}
			lock.Lock()
			contractBytecodes[common.HexToAddress(dirEntry.Name())] = bytecode
			lock.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, nil, fmt.Errorf("error loading contract bytecodes: %s", err)
	}
	fmt.Printf("OK\n")

	return pcTracesPaths, contractBytecodes, nil
}

func outputResults(processorResults chan pcTraceResult, expTotalResults int, contractsBytecodes map[common.Address][]byte) error {
	chunkerResults := make([]pcTraceResult, 0, expTotalResults)
	for i := 0; i < expTotalResults; i++ {
		result := <-processorResults
		if result.err != nil {
			return fmt.Errorf("error processing: %s", result.err)
		}
		chunkerResults = append(chunkerResults, result)
		if i%(expTotalResults/8) == 0 {
			fmt.Printf("Processing traces... %d%%\n", (i*100)/expTotalResults)
		}
	}
	var chunkerNames []string
	for _, cm := range chunkerResults[0].chunkersMetrics {
		chunkerNames = append(chunkerNames, cm.ChunkerName)
	}

	if err := genGasCSV(chunkerResults, chunkerNames); err != nil {
		return fmt.Errorf("error exporting gas csv: %s", err)
	}
	if err := genChunkedContractSizesCSV(chunkerResults, chunkerNames, contractsBytecodes); err != nil {
		return fmt.Errorf("error exporting gas csv: %s", err)
	}

	return nil
}

func genGasCSV(results []pcTraceResult, chunkerNames []string) error {
	csvGas, err := os.OpenFile("gas_analysis.csv", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not create file: %s", err)
	}
	csvGasWriter := csv.NewWriter(csvGas)
	defer csvGasWriter.Flush()
	columns := []string{"tx", "execution_length"}
	for _, cn := range chunkerNames {
		columns = append(columns, fmt.Sprintf("%s_gas", cn))
	}
	csvGasWriter.Write(columns)

	for _, result := range results {
		line := []string{result.tx[:10], fmt.Sprintf("%d", result.execLength)}
		for _, cm := range result.chunkersMetrics {
			line = append(line, fmt.Sprintf("%d", cm.Gas))
		}
		csvGasWriter.Write(line)
	}

	return nil
}

func genChunkedContractSizesCSV(results []pcTraceResult, chunkerNames []string, contractBytecodes map[common.Address][]byte) error {
	csvGas, err := os.OpenFile("chunker_contract_sizes.csv", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not create file: %s", err)
	}
	csvGasWriter := csv.NewWriter(csvGas)
	defer csvGasWriter.Flush()
	columns := []string{"contract_addr", "original_size"}
	for _, cn := range chunkerNames {
		columns = append(columns, fmt.Sprintf("%s_chunked_size", cn))
	}
	csvGasWriter.Write(columns)

	contractChunkedSizes := map[common.Address][]int{}
	for _, result := range results {
		for chunkerIdx, cm := range result.chunkersMetrics {
			for addr, size := range cm.ContractsChunkedSize {
				if contractChunkedSizes[addr] == nil {
					contractChunkedSizes[addr] = make([]int, len(chunkerNames))
				}
				contractChunkedSizes[addr][chunkerIdx] = size
			}
		}
	}
	for contractAddr, chunkedSizes := range contractChunkedSizes {
		line := []string{contractAddr.String(), fmt.Sprintf("%d", len(contractBytecodes[contractAddr]))}
		for _, size := range chunkedSizes {
			line = append(line, fmt.Sprintf("%d", size))
		}
		csvGasWriter.Write(line)
	}
	return nil
}
