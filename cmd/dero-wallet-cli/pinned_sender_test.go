// Copyright 2017-2021 DERO Project. All rights reserved.

package main

import (
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/walletapi"
)

// validTestAddress derives a syntactically valid DERO address whose network matches the
// current globals network, so ParseValidateAddress accepts it without any on-chain
// registration (the helper's parse is fast feedback only — registration/ring-membership is
// the engine's job, exercised by walletapi's Test_SenderPinGuard_* suite).
func validTestAddress(scalar int64) string {
	pt := new(bn256.G1).ScalarMult(crypto.G, big.NewInt(scalar))
	addr := rpc.NewAddressFromKeys((*crypto.Point)(pt))
	addr.Mainnet = globals.IsMainnet()
	return addr.String()
}

// Test_pinnedSenderFromInput pins down THE TRAP from the build handoff: blank input MUST
// produce the LITERAL zero-value TransferOptions (engine fast path, byte-identical to a
// plain default send), and MUST NEVER produce a non-nil-but-empty PinnedSender (which would
// route a default send down the engine's resolve-and-name path and error). A valid address
// must produce a non-nil PinnedSender carrying that address verbatim.
func Test_pinnedSenderFromInput(t *testing.T) {
	// blank / whitespace-only => zero value, PinnedSender stays nil.
	for _, blank := range []string{"", "   ", "\t", "  \t \n"} {
		opts := pinnedSenderFromInput(blank)
		if opts.PinnedSender != nil {
			t.Fatalf("blank input %q produced a non-nil PinnedSender (%+v); THE TRAP: blank MUST be the "+
				"zero-value TransferOptions, never an empty PinnedSender that errors the engine on a "+
				"send the user meant to be plain.", blank, opts.PinnedSender)
		}
		// must be the literal zero value across the whole struct (no Ring, no Attribution drift).
		if opts != (walletapi.TransferOptions{}) {
			t.Fatalf("blank input %q produced a non-zero TransferOptions %+v; want the literal zero value.", blank, opts)
		}
	}

	// an unparseable address => clean fallback to the zero value (the engine never sees it).
	badOpts := pinnedSenderFromInput("not-a-dero-address")
	if badOpts.PinnedSender != nil {
		t.Fatalf("unparseable address produced a non-nil PinnedSender (%+v); a parse failure must fall "+
			"back to the default attribution, not forward garbage to the engine.", badOpts.PinnedSender)
	}

	// a valid address (network-matched) => non-nil PinnedSender carrying the address verbatim.
	addr := validTestAddress(123456)
	goodOpts := pinnedSenderFromInput(addr)
	if goodOpts.PinnedSender == nil {
		t.Fatalf("valid address %q produced a nil PinnedSender; a manually entered ring-member address "+
			"must be forwarded to the engine.", addr)
	}
	if goodOpts.PinnedSender.Address != addr {
		t.Fatalf("PinnedSender.Address = %q, want the entered address verbatim %q.", goodOpts.PinnedSender.Address, addr)
	}

	// surrounding whitespace on a valid address must be trimmed, not rejected.
	trimmedOpts := pinnedSenderFromInput("   " + addr + "  ")
	if trimmedOpts.PinnedSender == nil || trimmedOpts.PinnedSender.Address != addr {
		t.Fatalf("padded valid address did not trim to %q (got %+v); leading/trailing space must be "+
			"stripped before the address is used.", addr, trimmedOpts.PinnedSender)
	}

	// NEGATIVE CONTROL (executed): prove the valid-address arm is genuinely exercising a parseable
	// address — if validTestAddress produced something ParseValidateAddress rejects, goodOpts above
	// would have been nil and the test would have a vacuous "valid" case.
	if _, err := globals.ParseValidateAddress(addr); err != nil {
		t.Fatalf("NEGATIVE CONTROL FAILED: validTestAddress produced %q which ParseValidateAddress rejects "+
			"(%v); the valid-address assertions above are testing nothing.", addr, err)
	}
}
