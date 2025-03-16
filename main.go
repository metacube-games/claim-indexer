package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type (
	StarknetEvent struct {
		FromAddress     string   `json:"from_address"`
		Keys            []string `json:"keys"`
		Data            []string `json:"data"`
		BlockHash       string   `json:"block_hash"`
		BlockNumber     int      `json:"block_number"`
		TransactionHash string   `json:"transaction_hash"`
	}
	RPCResponse struct {
		JsonRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			Events            []StarknetEvent `json:"events"`
			ContinuationToken *string         `json:"continuation_token,omitempty"`
		} `json:"result"`
		Error any `json:"error,omitempty"`
	}
	IndexerState struct {
		LastProcessedBlock int
		OwnershipState     map[string]map[string]struct{}
	}
	StateFile struct {
		Contracts map[string]struct {
			LastProcessedBlock int                 `json:"last_processed_block"`
			OwnershipState     map[string][]string `json:"ownership"`
		} `json:"contracts"`
	}
)

var (
	CONTRACTS = map[string]int{ // contract address -> deployment block
		"0x007ca74fd0a9239678cc6355e38ac1e7820141501727ae37f9c733e5ed1c3592": 636421,
		"0x0602c301f6a1c2ef174bafaab7389c3f6165df34736befcf2ca3df7764934caf": 645335,
	}
	TRANSFER_EVENT_KEY = "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9"
	API_URL            = ""
	STATE_FILE         = "/persistent/state.json"
	PORT               = 8080

	globalState map[string]*IndexerState
	stateMutex  sync.Mutex
)

func loadState() map[string]*IndexerState {
	state := make(map[string]*IndexerState)
	data, err := os.ReadFile(STATE_FILE)
	if err == nil {
		var stateFile StateFile
		if err = json.Unmarshal(data, &stateFile); err == nil {
			for contract, data := range stateFile.Contracts {
				ownershipState := make(map[string]map[string]struct{})
				for owner, tokens := range data.OwnershipState {
					set := make(map[string]struct{})
					for _, token := range tokens {
						set[token] = struct{}{}
					}
					ownershipState[owner] = set
				}
				state[contract] = &IndexerState{
					LastProcessedBlock: data.LastProcessedBlock,
					OwnershipState:     ownershipState,
				}
			}
		}
	}
	for contract, block := range CONTRACTS {
		if state[contract] == nil {
			state[contract] = &IndexerState{
				LastProcessedBlock: block - 1,
				OwnershipState:     make(map[string]map[string]struct{}),
			}
		}
	}
	return state
}

func saveState() {
	stateMutex.Lock()
	defer stateMutex.Unlock()

	stateFile := StateFile{
		Contracts: make(map[string]struct {
			LastProcessedBlock int                 `json:"last_processed_block"`
			OwnershipState     map[string][]string `json:"ownership"`
		}),
	}
	for contract, state := range globalState {
		ownershipState := make(map[string][]string)
		for owner, tokens := range state.OwnershipState {
			arr := make([]string, 0, len(tokens))
			for token := range tokens {
				arr = append(arr, token)
			}
			ownershipState[owner] = arr
		}
		stateFile.Contracts[contract] = struct {
			LastProcessedBlock int                 `json:"last_processed_block"`
			OwnershipState     map[string][]string `json:"ownership"`
		}{
			LastProcessedBlock: state.LastProcessedBlock,
			OwnershipState:     ownershipState,
		}
	}
	content, err := json.Marshal(stateFile)
	if err != nil {
		log.Println("Error saving state:", err)
		return
	}
	_ = os.WriteFile(STATE_FILE, content, 0644)

}

func getLatestBlockNumber(ctx context.Context) (int, error) {
	body := map[string]interface{}{
		"id":      1,
		"jsonrpc": "2.0",
		"method":  "starknet_blockNumber",
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, API_URL, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var out struct {
		Result int         `json:"result"`
		Error  interface{} `json:"error"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return 0, err
	}
	if out.Error != nil {
		return 0, fmt.Errorf("API error: %v", out.Error)
	}
	return out.Result, nil
}

func getEventsInRange(ctx context.Context, fromBlock, toBlock int, contract string) ([]StarknetEvent, error) {
	var all []StarknetEvent
	var contToken *string
	for {
		params := map[string]interface{}{
			"from_block": map[string]interface{}{"block_number": fromBlock},
			"to_block":   map[string]interface{}{"block_number": toBlock},
			"address":    contract,
			"keys":       [][]string{{TRANSFER_EVENT_KEY}},
			"chunk_size": 1000,
		}
		if contToken != nil {
			params["continuation_token"] = *contToken
		}
		body := map[string]interface{}{
			"id":      1,
			"jsonrpc": "2.0",
			"method":  "starknet_getEvents",
			"params":  []interface{}{params},
		}
		b, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, API_URL, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		rb, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var ev RPCResponse
		if err := json.Unmarshal(rb, &ev); err != nil {
			return nil, err
		}
		if ev.Error != nil {
			return nil, fmt.Errorf("API error: %v", ev.Error)
		}
		all = append(all, ev.Result.Events...)
		if ev.Result.ContinuationToken == nil {
			break
		}
		contToken = ev.Result.ContinuationToken
	}
	return all, nil
}

func updateState() {
	stateMutex.Lock()
	defer stateMutex.Unlock()

	ctx := context.Background()
	latest, err := getLatestBlockNumber(ctx)
	if err != nil {
		log.Println("Error getting latest block:", err)
		return
	}
	for contract := range CONTRACTS {
		state := globalState[contract]
		fromBlock := state.LastProcessedBlock + 1
		if fromBlock > latest {
			continue
		}
		events, err := getEventsInRange(ctx, fromBlock, latest, contract)
		if err != nil {
			log.Println("Error fetching events:", err)
			continue
		}
		for _, e := range events {
			if len(e.Keys) < 5 {
				continue
			}
			from := formatAddress(strings.ToLower(e.Keys[1]))
			to := formatAddress(strings.ToLower(e.Keys[2]))
			tLow := new(big.Int)
			tLow.SetString(e.Keys[3], 0)
			tHigh := new(big.Int)
			tHigh.SetString(e.Keys[4], 0)
			tokenID := new(big.Int).Lsh(tHigh, 128)
			tokenID.Add(tokenID, tLow)
			tIDStr := tokenID.String()

			fromBigInt := new(big.Int)
			_, ok := fromBigInt.SetString(from, 0)
			if !ok {
				log.Println("Invalid from address:", from)
				continue
			}

			toBigInt := new(big.Int)
			_, ok = toBigInt.SetString(to, 0)
			if !ok {
				log.Println("Invalid to address:", to)
				continue
			}

			log.Default().Printf(
				"Transfer %s from %s to %s, contract %s",
				fmt.Sprintf("%4s", tIDStr),
				prettyAddress(from),
				prettyAddress(to),
				prettyAddress(contract),
			)

			if fromBigInt.Cmp(big.NewInt(0)) != 0 {
				if sset, ok := state.OwnershipState[from]; ok {
					delete(sset, tIDStr)
					if len(sset) == 0 {
						delete(state.OwnershipState, from)
					}
				}
			}
			if toBigInt.Cmp(big.NewInt(0)) != 0 {
				if _, ok := state.OwnershipState[to]; !ok {
					state.OwnershipState[to] = make(map[string]struct{})
				}
				state.OwnershipState[to][tIDStr] = struct{}{}
			}
		}
		state.LastProcessedBlock = latest
	}
}

func formatAddress(addr string) string {
	addr = strings.TrimPrefix(addr, "0x")
	return "0x" + fmt.Sprintf("%064s", addr)
}

func prettyAddress(addr string) string {
	if len(addr) <= 18 {
		return addr
	}
	return fmt.Sprintf("%s...%s", addr[:10], addr[len(addr)-8:])
}

func main() {
	apiUrl := os.Getenv("API_URL")
	if apiUrl == "" {
		log.Fatal("API_URL is not set")
	}
	API_URL = apiUrl

	globalState = loadState()
	log.Default().Printf("Loaded state with %d contracts", len(globalState))
	go func() {
		for {
			updateState()
			saveState()
			time.Sleep(20 * time.Second)
		}
	}()

	router := gin.Default()
	router.GET("/owned/:contract/:address", func(c *gin.Context) {
		contract := strings.ToLower(c.Param("contract"))
		contract = formatAddress(contract)
		address := strings.ToLower(c.Param("address"))
		address = formatAddress(address)
		stateMutex.Lock()
		defer stateMutex.Unlock()
		state, ok := globalState[contract]
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "Contract not found"})
			return
		}
		tokens, ok := state.OwnershipState[address]
		if !ok {
			c.JSON(http.StatusOK, []string{})
			return
		}
		var arr []string
		for token := range tokens {
			arr = append(arr, token)
		}
		sort.Slice(arr, func(i, j int) bool {
			a, _ := strconv.ParseInt(arr[i], 10, 64)
			b, _ := strconv.ParseInt(arr[j], 10, 64)
			return a < b
		})
		c.JSON(http.StatusOK, arr)
	})
	router.Run(fmt.Sprintf(":%d", PORT))
}
