package main

// Copyright 2017-2021 DERO Project. All rights reserved.

import (
	"strings"

	"github.com/chzyer/readline"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/walletapi"
)

// promptPinnedSender asks for an OPTIONAL address to name as the sender in the
// receiver-decryptable attribution byte, then resolves it to a walletapi.TransferOptions.
// Manual entry ONLY — no heuristics and no address sourcing; any smart selection layer
// belongs in HOLOGRAM/dApps, not the CLI. The I/O is kept separate from the decision logic
// (pinnedSenderFromInput) so the trap-handling can be unit-tested without a terminal.
func promptPinnedSender(l *readline.Instance) walletapi.TransferOptions {
	raw, err := ReadString(l, "address to attribute as sender", "")
	if err != nil {
		return walletapi.TransferOptions{} // read error => zero value, never an empty PinnedSender
	}
	return pinnedSenderFromInput(raw)
}

// pinnedSenderFromInput turns a raw, user-entered string into a TransferOptions. It is the
// pure decision half of promptPinnedSender (no terminal, no globals other than the self-check)
// so the trap below is directly testable.
//
// THE TRAP: blank input returns the zero-value TransferOptions, which is byte-identical to
// today's default send. A non-nil-but-empty PinnedSender is NEVER returned: an empty address
// would push a plain default send down the engine's resolve-and-name path and error on a
// transfer the user meant to be ordinary. We gate strictly on a non-empty address.
//
// The parse check here is fast feedback, not the security boundary. The engine
// (TransferPayload0WithOptions) re-validates registration and ring-membership and forces a
// third-party target into the ring, returning a clean error on a bad target.
func pinnedSenderFromInput(raw string) walletapi.TransferOptions {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return walletapi.TransferOptions{}
	}

	// fast feedback only; on a parse failure fall back to the default attribution.
	a, perr := globals.ParseValidateAddress(raw)
	if perr != nil {
		logger.Error(perr, "Not a valid address; sending with default sender attribution")
		return walletapi.TransferOptions{}
	}
	if wallet != nil && a.BaseAddress().String() == wallet.GetAddress().BaseAddress().String() {
		// self-pin is allowed by the engine, but it names YOU as the sender to the
		// receiver; surface it so it is a deliberate choice rather than a slip.
		logger.Info("Pinning to your own address names you as the sender to the receiver.")
	}

	return walletapi.TransferOptions{PinnedSender: &walletapi.PinnedSender{Address: raw}}
}
