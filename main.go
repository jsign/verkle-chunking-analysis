package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/sync/errgroup"
)

type traceOutput struct {
	ContractsPCs map[common.Address][]uint64
	ReceiptGas   uint64
	To           common.Address
}

func main() {
	pcTraceFolderFlag := flag.String("tracespath", "", "Full path of the folder containing the traces")
	filterContractsChunksStatsFlag := flag.String("filter-contracts-chunks-stats", "", "Comma separated list of contract addresses to filter the chunks stats csv file.")
	flag.Parse()

	if *pcTraceFolderFlag == "" {
		fmt.Printf("Expected --tracespath <folder> flag\n")
		os.Exit(1)
	}
	pcTraceFolder := *pcTraceFolderFlag

	filterContractsChunksStatsStr := strings.Split(*filterContractsChunksStatsFlag, ",")
	filteredContractsChunksStats := make(map[common.Address]struct{}, len(filterContractsChunksStatsStr))
	for _, addrStr := range filterContractsChunksStatsStr {
		filteredContractsChunksStats[common.HexToAddress(addrStr)] = struct{}{}
	}

	pcTracePaths, contractBytecodes, err := loadData(pcTraceFolder, -1)
	if err != nil {
		log.Fatal(err)
	}

	numProcessors := runtime.NumCPU()
	sliceSize := len(pcTracePaths) / numProcessors
	processorResults := make(chan pcTraceResult)
	for i := 0; i < numProcessors; i++ {
		if i == numProcessors-1 {
			go processFiles(contractBytecodes, pcTracePaths[i*sliceSize:], filteredContractsChunksStats, processorResults)
		} else {
			go processFiles(contractBytecodes, pcTracePaths[i*sliceSize:(i+1)*sliceSize], filteredContractsChunksStats, processorResults)
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

func outputResults(
	processorResults chan pcTraceResult,
	expTotalResults int,
	contractsBytecodes map[common.Address][]byte) error {

	fanout := make([]chan pcTraceResult, 3)
	for i := range fanout {
		fanout[i] = make(chan pcTraceResult, 1_000)
	}

	chunkerNames := []string{"31bytechunker", "32bytechunker"} // TODO: fix
	group, _ := errgroup.WithContext(context.Background())
	group.Go(func() error {
		if err := genGasCSV(fanout[0], chunkerNames); err != nil {
			return fmt.Errorf("error exporting gas csv: %s", err)
		}
		return nil
	})
	group.Go(func() error {
		if err := genChunkedContractSizesCSV(fanout[1], chunkerNames, contractsBytecodes); err != nil {
			return fmt.Errorf("error exporting contracts chunked sizes csv: %s", err)
		}
		return nil
	})
	group.Go(func() error {
		if err := genChunksStatsCSV(fanout[2]); err != nil {
			return fmt.Errorf("error exporting chunks stats csv: %s", err)
		}
		return nil
	})

	for i := 0; i < expTotalResults; i++ {
		result := <-processorResults
		if result.err != nil {
			return fmt.Errorf("error processing: %s", result.err)
		}
		for i := 0; i < len(fanout); i++ {
			fanout[i] <- result
		}
		if i%(expTotalResults/8) == 0 {
			fmt.Printf("Processing traces... %d%%\n", (i*100)/expTotalResults)
		}
	}
	for i := range fanout {
		close(fanout[i])
	}
	if err := group.Wait(); err != nil {
		return fmt.Errorf("error exporting results: %s", err)
	}

	return nil
}

func genGasCSV(results chan pcTraceResult, chunkerNames []string) error {
	csvGas, err := os.OpenFile("gas_analysis.csv", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not create file: %s", err)
	}
	defer csvGas.Close()
	csvGasWriter := csv.NewWriter(csvGas)
	defer csvGasWriter.Flush()
	columns := []string{"tx", "execution_length", "receipt_gas", "to"}
	for _, cn := range chunkerNames {
		columns = append(columns, fmt.Sprintf("%s_gas", cn))
	}
	if err := csvGasWriter.Write(columns); err != nil {
		return fmt.Errorf("could not write csv header: %s", err)
	}

	for result := range results {
		line := []string{result.tx, fmt.Sprintf("%d", result.execLength), fmt.Sprintf("%d", result.receiptGas), result.to.Hex()}
		for _, cm := range result.chunkersMetrics {
			line = append(line, fmt.Sprintf("%d", cm.Gas))
		}
		if err := csvGasWriter.Write(line); err != nil {
			return fmt.Errorf("could not write csv line: %s", err)
		}
	}

	return nil
}

func genChunkedContractSizesCSV(results chan pcTraceResult, chunkerNames []string, contractBytecodes map[common.Address][]byte) error {
	csvGas, err := os.OpenFile("contracts_chunked_sizes.csv", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not create file: %s", err)
	}
	defer csvGas.Close()
	csvGasWriter := csv.NewWriter(csvGas)
	defer csvGasWriter.Flush()
	columns := []string{"contract_addr", "original_size"}
	for _, cn := range chunkerNames {
		columns = append(columns, fmt.Sprintf("%s_chunked_size", cn))
	}
	if err := csvGasWriter.Write(columns); err != nil {
		return fmt.Errorf("could not write csv header: %s", err)
	}

	contractChunkedSizes := map[common.Address][]int{}
	for result := range results {
		for chunkerIdx, cm := range result.chunkersMetrics {
			for addr, stats := range cm.ContractsStats {
				if contractChunkedSizes[addr] == nil {
					contractChunkedSizes[addr] = make([]int, len(chunkerNames))
				}
				contractChunkedSizes[addr][chunkerIdx] = stats.ChunkedSizeBytes
			}
		}
	}
	for contractAddr, chunkedSizes := range contractChunkedSizes {
		line := []string{contractAddr.String(), fmt.Sprintf("%d", len(contractBytecodes[contractAddr]))}
		for _, size := range chunkedSizes {
			line = append(line, fmt.Sprintf("%d", size))
		}
		if err := csvGasWriter.Write(line); err != nil {
			return fmt.Errorf("could not write csv line: %s", err)
		}
	}
	return nil
}

func genChunksStatsCSV(results chan pcTraceResult) error {
	fCsvGas, err := os.OpenFile("contracts_chunks_stats.csv", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not create file: %s", err)
	}
	defer fCsvGas.Close()
	csvChunksStatsWriter := csv.NewWriter(fCsvGas)
	defer csvChunksStatsWriter.Flush()

	columns := []string{"tx", "to", "contract_addr", "chunk_number", "bytes_used", "gas_used"}
	if err := csvChunksStatsWriter.Write(columns); err != nil {
		return fmt.Errorf("could not write csv header: %s", err)
	}

	for result := range results {
		for contractAddr, stats := range result.chunkersMetrics[0].ContractsStats {
			if len(stats.ChunksStats) == 0 {
				continue
			}
			line := []string{result.tx, result.to.Hex(), contractAddr.Hex()}
			for _, chunkStats := range stats.ChunksStats {
				line = append(line, strconv.Itoa(chunkStats.ChunkNumber))
				line = append(line, strconv.Itoa(chunkStats.AccessedBytes))
				line = append(line, strconv.FormatUint(chunkStats.ChargedGas, 10))
			}
			if err := csvChunksStatsWriter.Write(line); err != nil {
				return fmt.Errorf("could not write csv line: %s", err)
			}
		}
	}
	return nil
}

// tx, to, contractAddr, chunkNumber, bytes_used, gas_used

// Chunk stats (on average per tx):
//     - Accessed # code-chunks and would've charged {} code-access gas.
//     - Charged {} WITNESS_BRANCH_COSTs
//     - Charged {} WITNESS_CHUNK_COSTs
//     - Executed {} bytes (i.e: instruction bytes), and paid for {} bytes (i.e: chunks bytes)
//
// Txs on average involved executing {} contracts.
