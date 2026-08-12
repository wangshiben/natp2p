package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"bnfs_p2p/billingqueue"
	"bnfs_p2p/billingvoucher"
)

const (
	defaultMaxItems = uint64(65536)
	defaultMaxBytes = uint64(64 << 20)
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("billingqueue-inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("path", "", "persistent waitSubmit WAL path")
	maxItems := flags.Uint64("max-items", defaultMaxItems, "maximum live voucher count")
	maxBytes := flags.Uint64("max-bytes", defaultMaxBytes, "maximum live payload bytes")
	payerIDText := flags.String("payer-id", "", "target payer NodeID")
	relayIDText := flags.String("relay-id", "", "optional target Relay NodeID consistency check")
	payerKeyPath := flags.String("payer-key", "", "optional target payer private-key file")
	relayKeyPath := flags.String("relay-key", "", "target Relay private-key file")
	payerBillingKeyPath := flags.String("payer-billing-key", "", "optional independent payer billing private-key file")
	relayBillingKeyPath := flags.String("relay-billing-key", "", "optional independent Relay billing private-key file")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if *path == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "billingqueue-inspect: -path is required and positional arguments are not accepted")
		return 2
	}

	options, optionsErr := inspectionOptions(
		*payerIDText, *relayIDText, *payerKeyPath, *relayKeyPath,
		*payerBillingKeyPath, *relayBillingKeyPath,
	)
	if optionsErr != nil {
		fmt.Fprintln(stderr, "billingqueue-inspect: target_invalid")
		return 2
	}
	inspection, err := billingqueue.InspectWithOptions(*path, billingqueue.Limits{
		MaxItems: *maxItems,
		MaxBytes: *maxBytes,
	}, options)
	if err != nil {
		switch {
		case errors.Is(err, billingqueue.ErrCorrupt):
			fmt.Fprintln(stderr, "billingqueue-inspect: queue_corrupt")
		case errors.Is(err, os.ErrNotExist):
			fmt.Fprintln(stderr, "billingqueue-inspect: queue_not_found")
		default:
			fmt.Fprintln(stderr, "billingqueue-inspect: inspection_failed")
		}
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(inspection); err != nil {
		fmt.Fprintln(stderr, "billingqueue-inspect: output_failed")
		return 1
	}
	return 0
}

func inspectionOptions(
	payerIDText, relayIDText, payerKeyPath, relayKeyPath string,
	payerBillingKeyPath, relayBillingKeyPath string,
) (billingqueue.InspectionOptions, error) {
	var options billingqueue.InspectionOptions
	targeted := payerIDText != "" || relayIDText != "" || payerKeyPath != "" || relayKeyPath != "" ||
		payerBillingKeyPath != "" || relayBillingKeyPath != ""
	if !targeted {
		return options, nil
	}
	if payerIDText != "" {
		payerID, err := billingvoucher.ParseIdentifierHex(payerIDText)
		if err != nil {
			return billingqueue.InspectionOptions{}, err
		}
		options.PayerID = payerID
	}
	if relayIDText != "" {
		relayID, err := billingvoucher.ParseIdentifierHex(relayIDText)
		if err != nil {
			return billingqueue.InspectionOptions{}, err
		}
		options.RelayID = relayID
	}
	if payerKeyPath != "" {
		payerPrivateKey, err := loadPrivateKey(payerKeyPath)
		if err != nil {
			return billingqueue.InspectionOptions{}, err
		}
		options.PayerPublicKey = payerPrivateKey.PublicKey()
	}
	if relayKeyPath == "" {
		return billingqueue.InspectionOptions{}, errors.New("targeted inspection requires a Relay private key")
	}
	relayPrivateKey, err := loadPrivateKey(relayKeyPath)
	if err != nil {
		return billingqueue.InspectionOptions{}, err
	}
	options.RelayPublicKey = relayPrivateKey.PublicKey()
	if payerBillingKeyPath != "" {
		payerBillingPrivateKey, err := loadPrivateKey(payerBillingKeyPath)
		if err != nil {
			return billingqueue.InspectionOptions{}, err
		}
		options.PayerBillingPublicKey = payerBillingPrivateKey.PublicKey()
	}
	if relayBillingKeyPath != "" {
		relayBillingPrivateKey, err := loadPrivateKey(relayBillingKeyPath)
		if err != nil {
			return billingqueue.InspectionOptions{}, err
		}
		options.RelayBillingPublicKey = relayBillingPrivateKey.PublicKey()
	}
	if options.PayerID == (billingvoucher.Identifier{}) && options.PayerPublicKey == nil {
		return billingqueue.InspectionOptions{}, errors.New("targeted inspection requires a payer identity")
	}
	return options, nil
}

func loadPrivateKey(path string) (*ecdh.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		file.Close()
		return nil, errors.New("private key path is not a small regular file")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 4097))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil || len(encoded) > 4096 {
		return nil, errors.New("private key file could not be read")
	}
	privateKeyBytes, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(privateKeyBytes) != 32 {
		return nil, errors.New("private key file is invalid")
	}
	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, errors.New("private key file is invalid")
	}
	return privateKey, nil
}
