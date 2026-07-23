package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"bnfs_p2p/test/local-chaos/billingadversary"
)

const maximumRequestBytes = 16 * 1024

func main() {
	stateDir := flag.String("state-dir", "", "private directory for component probe queue state")
	flag.Parse()
	if *stateDir == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "billing adversary component probe: invalid arguments")
		os.Exit(2)
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "billing adversary component probe: state directory unavailable")
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), maximumRequestBytes)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		request, err := decodeRequest(scanner.Bytes())
		var result billingadversary.Result
		if err != nil {
			result = billingadversary.Result{
				SchemaVersion:      1,
				Scenario:           "invalid",
				Status:             "FAIL",
				FailureCode:        "component_probe_invalid_request",
				Checks:             []string{},
				ProductionPackages: []string{},
				Limitations:        []string{"component_probe_not_full_p2p_socket_path"},
			}
		} else {
			request.StateDir = *stateDir
			result = billingadversary.Run(request)
		}
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, "billing adversary component probe: output failed")
			os.Exit(1)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "billing adversary component probe: input failed")
		os.Exit(1)
	}
}

func decodeRequest(encoded []byte) (billingadversary.Request, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var request billingadversary.Request
	if err := decoder.Decode(&request); err != nil {
		return billingadversary.Request{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return billingadversary.Request{}, fmt.Errorf("trailing JSON data")
	}
	return request, nil
}
