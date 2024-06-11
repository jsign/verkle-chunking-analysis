package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
)

type PCTrace map[string][]int

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
		var pcTrace PCTrace
		if err := json.Unmarshal(pcTraceBytes, &pcTrace); err != nil {
			log.Fatal(err)
		}
		result, err := processTrace(pcTrace)
		if err != nil {
			log.Fatal(err)
		}
		if result.numCodeChunks > 5 {
			fmt.Printf("%s: %d\n", dirEntry.Name(), result.numCodeChunks)
		}
	}
}

type Result struct {
	numCodeChunks int
}

func processTrace(trace PCTrace) (Result, error) {
	accessEvents := state.NewAccessEvents(nil)

	var result Result
	for contractAddressStr, pcs := range trace {
		contractAddr := common.HexToAddress(contractAddressStr)
		for _, pc := range pcs {
			gas := accessEvents.CodeChunksRangeGas(contractAddr, uint64(pc), 1, 1, false)
			if gas > 0 {
				result.numCodeChunks++
			}
		}
	}

	return result, nil
}
