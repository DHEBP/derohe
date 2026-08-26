// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package proof

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// A Bundle carries everything Prove needs, so a receiver can verify a payment
// without asking a block explorer or any other third party.
//
// Prove already works offline -- it does pure arithmetic over its arguments and
// touches no network. What was missing is that its two bulk inputs (the raw
// transaction and the completed ring) were only ever assembled inside the
// explorer, which is Prove's sole caller in this tree. A sender holds all of
// them at send time, so the sender can hand the receiver a Bundle directly.
//
// The txid is carried and checked rather than assumed. Prove itself never looks
// at a txid: it matches the proof against the transaction's payloads, so a
// bundle whose tx blob was swapped for a different transaction the same proof
// happens to open would verify silently. Binding the blob to a txid the receiver
// can quote is what makes the result referenceable afterwards.
type Bundle struct {
	Version int    `json:"version"`
	Network string `json:"network"` // "mainnet" or "testnet"
	TXID    string `json:"txid"`    // hex, must equal the hash of TxHex
	TxHex   string `json:"tx_hex"`  // raw serialized transaction
	// Ring is the completed ring member list, one slice per payload, in the
	// same shape the daemon returns -- transactions store compressed keys, so
	// the addresses cannot be recovered from TxHex alone.
	Ring  [][]string `json:"ring"`
	Proof string     `json:"proof"` // the deroproof... string
}

// BundleVersion is the current bundle format version.
const BundleVersion = 1

// Result is what a verified bundle yields.
type Result struct {
	TXID        string
	Receivers   []string
	Amounts     []uint64
	Payloads    []string
	RawPayloads [][]byte
}

// NewBundle assembles a bundle from the parts a sender already holds.
func NewBundle(network, txhex string, ring [][]string, proof string) *Bundle {
	b := &Bundle{
		Version: BundleVersion,
		Network: network,
		TxHex:   strings.TrimSpace(txhex),
		Ring:    ring,
		Proof:   strings.TrimSpace(proof),
	}
	if txid, err := txidOf(b.TxHex); err == nil {
		b.TXID = txid
	}
	return b
}

// Marshal renders the bundle as indented JSON, suitable for handing to a
// receiver over any channel.
func (b *Bundle) Marshal() ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

// UnmarshalBundle parses a bundle. It deliberately does not verify -- call
// Verify for that, so a caller cannot mistake parsing for proving.
func UnmarshalBundle(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("bundle is not valid json: %v", err)
	}
	return &b, nil
}

// txidOf deserializes a raw transaction and returns its hash.
//
// transaction.Deserialize PANICS on some malformed input rather than returning
// an error -- a corrupted ring key reaches bn256 point decompression, which
// panics with "bn256: Cannot decompress" (transaction.go, the Deserialize ring
// loop). Verified by test: TestBundleRejectsTamperedTransaction crashes the
// process without this recover.
//
// A bundle arrives from whoever paid you, so it is untrusted input by
// construction. Recovering here keeps a hostile bundle from killing the
// receiver's wallet. The fix belongs at this boundary rather than in
// transaction/, which is consensus code we deliberately keep byte-identical to
// upstream.
func txidOf(txhex string) (txid string, err error) {
	defer func() {
		if r := recover(); r != nil {
			txid = ""
			err = fmt.Errorf("tx_hex is not a valid transaction: %v", r)
		}
	}()

	raw, err := hex.DecodeString(strings.TrimSpace(txhex))
	if err != nil {
		return "", fmt.Errorf("tx_hex is not valid hex: %v", err)
	}
	var tx transaction.Transaction
	if err = tx.Deserialize(raw); err != nil {
		return "", fmt.Errorf("tx_hex is not a valid transaction: %v", err)
	}
	return tx.GetHash().String(), nil
}

// Verify checks the bundle end to end with no network access whatsoever, and
// returns what the proof opens.
//
// It fails closed: any inconsistency is an error, never a partial result.
func (b *Bundle) Verify() (result *Result, err error) {
	// Prove parses ring addresses and decompresses curve points from the same
	// untrusted bundle, and those paths panic rather than erroring on malformed
	// input (see txidOf). Fail closed instead of crashing the caller.
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("bundle is malformed: %v", r)
		}
	}()

	if b == nil {
		return nil, fmt.Errorf("nil bundle")
	}
	if b.Version != BundleVersion {
		return nil, fmt.Errorf("unsupported bundle version %d, expected %d", b.Version, BundleVersion)
	}

	var mainnet bool
	switch b.Network {
	case "mainnet":
		mainnet = true
	case "testnet":
		mainnet = false
	default:
		return nil, fmt.Errorf("unknown network %q, expected mainnet or testnet", b.Network)
	}

	if strings.TrimSpace(b.Proof) == "" {
		return nil, fmt.Errorf("bundle carries no proof")
	}
	if strings.TrimSpace(b.TxHex) == "" {
		return nil, fmt.Errorf("bundle carries no transaction")
	}
	if len(b.Ring) == 0 {
		return nil, fmt.Errorf("bundle carries no ring members")
	}

	// Enforce the declared network against the proof itself.
	//
	// Prove's mainnet argument does NOT validate anything -- it is used at a
	// single line to set the rendering of the returned receiver address. So a
	// mainnet proof "verifies" as testnet and hands back a testnet-formatted
	// address for a real mainnet payment. The proof string is itself an address
	// and carries its own network, so check the two agree rather than leaving
	// the field decorative.
	if proofAddr, perr := rpc.NewAddress(strings.TrimSpace(b.Proof)); perr == nil {
		if proofAddr.IsMainnet() != mainnet {
			return nil, fmt.Errorf("bundle declares network %q but the proof is for %s",
				b.Network, networkName(proofAddr.IsMainnet()))
		}
	}

	// Bind the blob to the txid before proving anything. A caller who skips
	// this and calls Prove directly gets a correct amount attached to a
	// transaction they cannot name.
	actual, err := txidOf(b.TxHex)
	if err != nil {
		return nil, err
	}
	if b.TXID != "" && !strings.EqualFold(strings.TrimSpace(b.TXID), actual) {
		return nil, fmt.Errorf("bundle txid mismatch: claims %s, transaction hashes to %s", b.TXID, actual)
	}

	receivers, amounts, raw, decoded, err := Prove(b.Proof, b.TxHex, b.Ring, mainnet)
	if err != nil {
		return nil, err
	}
	if len(receivers) == 0 || len(amounts) == 0 {
		return nil, fmt.Errorf("proof opened nothing")
	}

	return &Result{
		TXID:        actual,
		Receivers:   receivers,
		Amounts:     amounts,
		Payloads:    decoded,
		RawPayloads: raw,
	}, nil
}

// networkName renders a network flag for error messages.
func networkName(mainnet bool) string {
	if mainnet {
		return "mainnet"
	}
	return "testnet"
}
