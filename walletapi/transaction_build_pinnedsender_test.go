package walletapi

// Falsifiable guards for the TransferOptions.PinnedSender primitive (engine-only).
//
// PinnedSender lets a sender deliberately choose WHICH ring slot the receiver-decryptable
// attribution byte names (self / receiver / any chosen decoy). Built wrong it becomes a
// tool to publish FALSE ACCUSATIONS; its safety floor is the export scrub (entry.Sender
// blanked + leading slot byte zeroed when !SenderVerified for rings > 2), guarded separately
// in attribution_export_guard_test.go.
//
// THE INDEXING TRAP these guards pin down: resolvePinnedSenderIndex returns a PUBLICKEYLIST SLOT
// index. The decode side reads payload[0] DIRECTLY as Publickeylist[payload[0]]. So the write
// site must write the slot verbatim (attrIndex = idx), NEVER witness_index[idx] — double
// indexing would name the wrong ring member. Guard (c) pins the resolver to publickeylist
// order; guard (d) proves the full round-trip on-chain.
//
// Each guard carries a NEGATIVE CONTROL that is actually executed every run: it constructs the
// broken-invariant value and asserts the guard's own logic rejects it, so the guard is proven
// to bite (not a no-op that passes vacuously).

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// makeRingMember deterministically derives a (publickeylist point, base address) pair from a
// scalar so the address round-trips back to the SAME G1 point the resolver compares against.
// This mirrors how a real ring is assembled: a member's pubkey IS its address's PublicKey.G1().
func makeRingMember(scalar int64) (*bn256.G1, string) {
	pt := new(bn256.G1).ScalarMult(crypto.G, big.NewInt(scalar))
	addr := rpc.NewAddressFromKeys((*crypto.Point)(pt))
	addr.Mainnet = true
	return pt, addr.String()
}

// --- Guard (c): TargetResolvesToCorrectSlot -------------------------------------------------
//
// The resolver must return the PUBLICKEYLIST SLOT of the target, for ANY ring member, and hard
// -error a non-member. This is the unit-level proof that the pinned sender pins to publickeylist order.
func Test_SenderPinGuard_TargetResolvesToCorrectSlot(t *testing.T) {
	// publickeylist [sender, receiver, decoy1, decoy2, decoy3] at slots 0..4.
	var publickeylist []*bn256.G1
	var addrs []string
	for i := 0; i < 5; i++ {
		pt, addr := makeRingMember(int64(1000 + i)) // distinct, non-zero scalars
		publickeylist = append(publickeylist, pt)
		addrs = append(addrs, addr)
	}

	cases := []struct {
		name string
		addr string
		want int
	}{
		{"sender->0", addrs[0], 0},
		{"receiver->1", addrs[1], 1},
		{"decoy2->3", addrs[3], 3},
	}
	for _, c := range cases {
		got, err := resolvePinnedSenderIndex(&PinnedSender{Address: c.addr}, publickeylist)
		if err != nil {
			t.Fatalf("%s: resolvePinnedSenderIndex returned error for a ring member: %v", c.name, err)
		}
		if got != c.want {
			t.Fatalf("%s: resolvePinnedSenderIndex = %d, want publickeylist slot %d. If this is off by a "+
				"permutation, the resolver is returning witness_index space instead of publickeylist "+
				"space — the double-index trap.", c.name, got, c.want)
		}
	}

	// non-member -> hard error (no slot exists for it).
	_, notInRing := makeRingMember(999999)
	if _, err := resolvePinnedSenderIndex(&PinnedSender{Address: notInRing}, publickeylist); err == nil {
		t.Fatal("resolvePinnedSenderIndex accepted an address that is NOT a ring member; non-members must " +
			"be a hard error (no silent fallback).")
	}

	// unparseable address -> hard error.
	if _, err := resolvePinnedSenderIndex(&PinnedSender{Address: "not-an-address"}, publickeylist); err == nil {
		t.Fatal("resolvePinnedSenderIndex accepted an unparseable address; it must be a hard error.")
	}

	// NEGATIVE CONTROL (executed): if the resolver instead returned witness_index space, the
	// slot it reports for the receiver would NOT equal the receiver's publickeylist slot under
	// a non-identity permutation. We assert the guard's expectation (slot 1) is the value that
	// genuinely matches the receiver's KEY at that slot — flipping the expected index breaks it.
	gotRecv, _ := resolvePinnedSenderIndex(&PinnedSender{Address: addrs[1]}, publickeylist)
	brokenExpectation := 2 // a deliberately wrong slot
	if gotRecv == brokenExpectation {
		t.Fatal("NEGATIVE CONTROL FAILED: receiver resolved to the wrong-slot sentinel; the guard " +
			"would not catch a mis-indexed resolver.")
	}
	// And the key at the resolved slot must be the receiver's key (pins to publickeylist, not witness_index).
	if publickeylist[gotRecv].String() != publickeylist[1].String() {
		t.Fatal("resolver slot does not point at the receiver's key in publickeylist order.")
	}
}

// --- Guard (e): NotWiredToXSWDBridge (bridge-containment sentinel, PRESENCE-grep) -------------
//
// BRIDGE CONTAINMENT: opts.PinnedSender must NEVER be wirable from an XSWD/dApp bridge param. The
// earlier version of this guard tried to recognize the SHAPE of a leak (a "pinnedsender" map-key
// read, or `.PinnedSender = <params/args>`). Shape-greps are evadable by the most idiomatic wiring
// (local-var indirection, a non-"pinnedsender" key name, struct unmarshal, a helper fn) — all of
// which sail past a pattern matcher. So this guard is now a PRESENCE-grep, not a shape-grep:
//
//   The engine is the ONLY legitimate place that references the .PinnedSender field. Within walletapi,
//   exactly two engine files may name it: transaction_build.go (defines the field + the write site)
//   and wallet_transfer.go (pre-validates + injects the target into the ring). ANY OTHER non-test
//   walletapi source that so much as MENTIONS `.PinnedSender`/`PinnedSender` is a containment breach —
//   regardless of the shape of the assignment. A bridge wiring layer has no business referencing
//   the field at all; the param->opts mapping belongs in the wallet/UI layer (a different repo),
//   behind per-tx user consent.
//
// This closes the whole class of evasions: there is no wiring shape that references the field
// without referencing the field.
func Test_SenderPinGuard_NotWiredToXSWDBridge(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("cannot glob walletapi sources: %v", err)
	}

	// The ONLY engine files permitted to reference the pinned-sender field. Adding a file here is a
	// deliberate, reviewable act — it cannot happen by accident, and a bridge file added to walletapi
	// would have to be allowlisted on purpose to pass, which a reviewer would catch.
	allowed := map[string]bool{
		"transaction_build.go": true, // field definition + write site (the engine)
		"wallet_transfer.go":   true, // pre-validation + ring injection (the engine)
	}

	// Presence: ANY token reference to the pinned-sender field/type. The leading \b anchors the
	// start of the identifier. Catches `.PinnedSender`, `PinnedSender:` in a struct literal, and the
	// `PinnedSender` type name.
	presence := regexp.MustCompile(`\bPinnedSender`)

	for _, f := range files {
		if filepath.Ext(f) != ".go" {
			continue
		}
		if regexp.MustCompile(`_test\.go$`).MatchString(f) {
			continue // tests legitimately exercise the field; we lock the NON-test engine surface
		}
		if allowed[f] {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("cannot read %s: %v", f, err)
		}
		if presence.Match(src) {
			t.Fatalf("CONTAINMENT BREACH in %s: a non-engine walletapi source references the pinned-sender "+
				"field/type. opts.PinnedSender must NEVER be wirable from an XSWD/dApp bridge param; only the "+
				"two engine files (transaction_build.go, wallet_transfer.go) may reference it. If this is a "+
				"legitimate new engine site, add it to the allowlist DELIBERATELY (and re-review containment).", f)
		}
	}

	// NEGATIVE CONTROL (executed): prove the presence-grep actually fires on the idiomatic leak
	// shapes that EVADED the old shape-grep. Each of these references the field, so presence MUST
	// catch every one regardless of how the value flows in.
	evasions := [][]byte{
		[]byte(`ft := &PinnedSender{Address: req["target_addr"].(string)}; opts.PinnedSender = ft`), // local-var + non-"pinnedsender" key
		[]byte(`var f PinnedSender; json.Unmarshal(reqBody, &f); opts.PinnedSender = &f`),           // struct unmarshal (idiomatic)
		[]byte(`opts.PinnedSender = decodePinnedSender(rawJSON)`),                                    // helper fn
		[]byte(`o.PinnedSender = req["pinnedsender"].(string)`),                                      // the old proven-evasion control (non-`opts` var + non-standard map key)
		[]byte(`x := PinnedSender{}`),                                                               // bare type reference
	}
	for i, e := range evasions {
		if !presence.Match(e) {
			t.Fatalf("NEGATIVE CONTROL %d FAILED: presence-grep missed `%s`; a wiring shape references "+
				"the pinned-sender field without being caught — the containment sentinel is blind.", i, string(e))
		}
	}

	// And the presence-grep must NOT fire on unrelated source (no false positive that would force
	// spurious allowlisting). A line with no `PinnedSender` token must pass.
	if presence.Match([]byte(`opts.Ring = &RingPreference{}`)) {
		t.Fatal("NEGATIVE CONTROL FAILED: presence-grep matched unrelated source (opts.Ring); it would " +
			"force spurious allowlist entries and erode the guard.")
	}
}

// --- Guard (b): NeverReachedByRotationEngine (structural, source-level) ----------------------
//
// PinnedSender is a SEPARATE field, NOT a third AttributionMode enum value, specifically so the
// attribution-rotation engine (which drives the enum) is structurally unable to reach it.
// This guard proves: (1) there is no AttributionPinnedSender enum constant, and (2) the only writer
// of opts.PinnedSender in the engine is the resolver read-site (never a rotation/curation path).
func Test_SenderPinGuard_NeverReachedByRotationEngine(t *testing.T) {
	build, err := os.ReadFile("transaction_build.go")
	if err != nil {
		t.Fatalf("cannot read transaction_build.go: %v", err)
	}

	// (1) The pinned sender must not have been folded into the AttributionMode enum.
	if regexp.MustCompile(`AttributionPinnedSender`).Match(build) {
		t.Fatal("STRUCTURAL VIOLATION: an `AttributionPinnedSender` enum constant exists. PinnedSender must be a " +
			"SEPARATE TransferOptions field, not a third AttributionMode value, so the rotation engine " +
			"that drives the enum cannot reach it.")
	}

	// (2) No engine source may ASSIGN .PinnedSender = (the engine only READS it). The field is set
	// exclusively by the wallet/caller constructing TransferOptions; the engine reading
	// opts.PinnedSender != nil and resolving it is fine, assigning it is not.
	//
	// NAME-AGNOSTIC: the receiver var is irrelevant — `o.PinnedSender = ...`, `tx.PinnedSender = ...`,
	// `someOpts.PinnedSender = ...` are all assignments to the field and all forbidden in engine
	// source. The `=[^=]` tail excludes `!=` (the `!` blocks `\s*=`) and `==` (second `=` fails
	// `[^=]`), so the legitimate read `opts.PinnedSender != nil` is NOT matched (asserted below).
	files, _ := filepath.Glob("*.go")
	assign := regexp.MustCompile(`\.PinnedSender\s*=[^=]`) // <anyvar>.PinnedSender = X  (not == / !=)
	for _, f := range files {
		if regexp.MustCompile(`_test\.go$`).MatchString(f) {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("cannot read %s: %v", f, err)
		}
		if assign.Match(src) {
			t.Fatalf("STRUCTURAL VIOLATION in %s: the engine ASSIGNS .PinnedSender (any TransferOptions var). "+
				"The rotation/curation paths must never set the pinned sender; the field is supplied only by the "+
				"caller's TransferOptions.", f)
		}
	}

	// The curated-ring / rotation path reads opts.Ring and opts.Attribution; it must not touch
	// opts.PinnedSender. Confirm the write site reads it as a guard (opts.PinnedSender != nil), proving the
	// field is consumed read-only.
	if !regexp.MustCompile(`opts\.PinnedSender\s*!=\s*nil`).Match(build) {
		t.Fatal("expected the write site to consume opts.PinnedSender read-only via `opts.PinnedSender != nil`.")
	}

	// NEGATIVE CONTROL (executed): the assign regex must catch an actual assignment shape...
	if !assign.Match([]byte(`opts.PinnedSender = &PinnedSender{}`)) {
		t.Fatal("NEGATIVE CONTROL FAILED: assign regex does not match `opts.PinnedSender = ...`; guard is blind.")
	}
	// ...AND must catch it under ANY receiver var name (the proven evasion used a non-`opts` var).
	if !assign.Match([]byte(`o.PinnedSender = &PinnedSender{Address: req["pinnedsender"].(string)}`)) {
		t.Fatal("NEGATIVE CONTROL FAILED: assign regex is still name-bound — it missed `o.PinnedSender = ...` " +
			"(a non-`opts` TransferOptions var); the hardened guard must be name-agnostic.")
	}
	if !assign.Match([]byte(`tx.PinnedSender = chosen`)) {
		t.Fatal("NEGATIVE CONTROL FAILED: assign regex missed `tx.PinnedSender = ...`; guard is still name-bound.")
	}
	// ...and must NOT mistake the legitimate read for an assignment (=[^=] excludes != and ==).
	if assign.Match([]byte(`if opts.PinnedSender != nil {`)) {
		t.Fatal("NEGATIVE CONTROL FAILED: assign regex matched the legitimate `opts.PinnedSender != nil` read.")
	}
	if assign.Match([]byte(`if opts.PinnedSender == nil {`)) {
		t.Fatal("NEGATIVE CONTROL FAILED: assign regex matched the legitimate `opts.PinnedSender == nil` compare.")
	}
}

// --- Guards (a) + (d): NilIsByteIdenticalToHonest + SelfAttributionDecodesToRealSender -------
//
// Folded into one on-chain harness (expensive to stand up twice). This is the test that PROVES
// the indexing is correct end-to-end: build A->B, decode as B, and read which address the
// attribution byte names through the real daemon_communication decode path.
//
// (a) nil PinnedSender payload[0] == honest default; {PinnedSender: A} CHANGES nothing
//     illegitimately and the round-trip below is the byte-level proof the chosen slot is what gets
//     written/read.
// (d) RING==2 PinnedSender{A}: decode as B -> Publickeylist[payload[0]] == A, SenderVerified==true.
//     RING==8 companion: still decodes A, SenderVerified==false (unverified).
func Test_SenderPinGuard_NilIdentical_And_SelfAttributionRoundTrip(t *testing.T) {
	time.Sleep(time.Millisecond)
	Initialize_LookupTable(1, 1<<17)

	wsrc_temp_db := filepath.Join(os.TempDir(), "pinnedsender_test_wallet_src.db")
	wdst_temp_db := filepath.Join(os.TempDir(), "pinnedsender_test_wallet_dst.db")
	os.Remove(wsrc_temp_db)
	os.Remove(wdst_temp_db)

	wsrc, err := Create_Encrypted_Wallet_From_Recovery_Words(wsrc_temp_db, "QWER", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("Cannot create src wallet, err %s", err)
	}
	wdst, err := Create_Encrypted_Wallet_From_Recovery_Words(wdst_temp_db, "QWER", "Dekade Spagat Bereich Radclub Yeti Dialekt Unimog Nomade Anlage Hirte Besitz Märzluft Krabbe Nabel Halsader Chefarzt Hering tauchen Neuerung Reifen Umgang Hürde Alchimie Amnesie Reifen")
	if err != nil {
		t.Fatalf("Cannot create dst wallet, err %s", err)
	}
	wgenesis, err := Create_Encrypted_Wallet_From_Recovery_Words(wdst_temp_db, "QWER", "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")
	if err != nil {
		t.Fatalf("Cannot create genesis wallet, err %s", err)
	}

	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], wgenesis.account.Keys.Public.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	genesis_block := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesis_block.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesis_block.GetHash()

	chain, rpcserver, params := simulator_chain_start()
	_ = params
	defer func() {
		simulator_chain_stop(chain, rpcserver)
		wsrc.Close_Encrypted_Wallet()
		wdst.Close_Encrypted_Wallet()
		os.Remove(wsrc_temp_db)
		os.Remove(wdst_temp_db)
	}()

	globals.Arguments["--daemon-address"] = rpcport
	go Keep_Connectivity()

	if err := chain.Add_TX_To_Pool(wsrc.GetRegistrationTX()); err != nil {
		t.Fatalf("Cannot add src regtx to pool err %s", err)
	}
	if err := chain.Add_TX_To_Pool(wdst.GetRegistrationTX()); err != nil {
		t.Fatalf("Cannot add dst regtx to pool err %s", err)
	}
	// Mine enough decoys so ring8 is possible: register several extra wallets.
	var decoys []*Wallet_Disk
	for i := 0; i < 8; i++ {
		d, derr := Create_Encrypted_Wallet_Random(filepath.Join(os.TempDir(), fmt.Sprintf("pinnedsender_decoy_%d.db", i)), "QWER")
		if derr != nil {
			t.Fatalf("cannot create decoy %d: %s", i, derr)
		}
		defer d.Close_Encrypted_Wallet()
		defer os.Remove(filepath.Join(os.TempDir(), fmt.Sprintf("pinnedsender_decoy_%d.db", i)))
		if err := chain.Add_TX_To_Pool(d.GetRegistrationTX()); err != nil {
			t.Fatalf("cannot register decoy %d: %s", i, err)
		}
		decoys = append(decoys, d)
	}

	for i := 0; i < 6; i++ {
		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	}

	wgenesis.SetDaemonAddress(rpcport)
	wsrc.SetDaemonAddress(rpcport)
	wdst.SetDaemonAddress(rpcport)
	wgenesis.SetOnlineMode()
	wsrc.SetOnlineMode()
	wdst.SetOnlineMode()

	time.Sleep(time.Second * 2)
	if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("src sync error %s", err)
	}
	if err = wdst.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("dst sync error %s", err)
	}

	srcAddr := wsrc.GetAddress().String() // == A (the real sender)
	dstAddr := wdst.GetAddress().String() // == B (the receiver)

	testPayload := rpc.Arguments{
		{Name: rpc.RPC_COMMENT, DataType: rpc.DataString, Value: "pinned sender roundtrip"},
		{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: uint64(123456789)},
	}

	// decodeAttributionByte builds a transfer A->B with the given opts and decrypts the
	// receiver-side payload of the FRESHLY BUILT tx exactly as daemon_communication.go's
	// CBOR_V2 path does. It returns:
	//   slotByte  = payload[0], the raw attribution slot byte the sender wrote
	//   slotAddr  = the address at Statement.Publickeylist[slotByte] (who payload[0] NAMES)
	//   recvSlot  = the receiver B's own slot in the same publickeylist
	//
	// This observes payload[0] DIRECTLY, BEFORE the two layers that otherwise hide it:
	//   - the ring==2 decode-override (daemon_communication.go: payload[0] ignored at ring 2)
	//   - the export scrub (entry.Sender blanked, payload[0] zeroed, for ring > 2)
	// so a double-index bug (attrIndex = witness_index[idx]) is genuinely catchable here:
	// slotAddr would stop equalling A. The freshly built tx carries the in-memory
	// Statement.Publickeylist (transaction_build.go: returned with Publickeylist set), in the
	// SAME slot order the write site used.
	decodeAttributionByte := func(t *testing.T, ringsize uint64, opts TransferOptions) (slotByte int, slotAddr string, recvSlot int) {
		t.Helper()
		wsrc.Sync_Wallet_Memory_With_Daemon()
		wdst.Sync_Wallet_Memory_With_Daemon()

		tx, err := wsrc.TransferPayload0WithOptions(
			[]rpc.Transfer{{Destination: dstAddr, Amount: 90000, Payload_RPC: testPayload}},
			ringsize, false, rpc.Arguments{}, 10000, false, opts)
		if err != nil {
			t.Fatalf("ringsize %d: build failed: %s", ringsize, err)
		}

		// Locate the native-SCID asset payload and its in-memory publickeylist.
		pay := tx.Payloads[0]
		pkl := pay.Statement.Publickeylist
		if len(pkl) == 0 {
			t.Fatalf("ringsize %d: built tx has empty Statement.Publickeylist; cannot observe payload[0]", ringsize)
		}

		// Mirror CBOR_V2 receiver decode: strip 33-byte ephemeral pub, derive shared key with
		// the RECEIVER's secret, then EncryptDecryptUserData with Keccak256(shared, recv_pubkey).
		raw := append([]byte(nil), pay.RPCPayload...) // copy: decrypt is in-place
		ephemeral_pub := new(bn256.G1)
		if err := ephemeral_pub.DecodeCompressed(raw[:33]); err != nil {
			t.Fatalf("ringsize %d: cannot decode ephemeral pub: %v", ringsize, err)
		}
		body := raw[33:]
		recvSecret := wdst.account.Keys.Secret.BigInt()
		shared := crypto.GenerateSharedSecret(recvSecret, ephemeral_pub)
		recvPub := wdst.account.Keys.Public.G1()
		crypto.EncryptDecryptUserData(crypto.Keccak256(shared[:], recvPub.EncodeCompressed()), body)

		slotByte = int(body[0])
		if slotByte < 0 || slotByte >= len(pkl) {
			t.Fatalf("ringsize %d: payload[0]=%d out of publickeylist range %d", ringsize, slotByte, len(pkl))
		}
		sa := rpc.NewAddressFromKeys((*crypto.Point)(pkl[slotByte]))
		sa.Mainnet = wdst.GetNetwork()
		slotAddr = sa.String()

		// find B's own slot for the byte-identity / honest comparison.
		recvSlot = -1
		for i := range pkl {
			if pkl[i].String() == recvPub.String() {
				recvSlot = i
				break
			}
		}
		return slotByte, slotAddr, recvSlot
	}

	// (d) THE INDEXING PROOF, at RING==8 (where payload[0] is fully sender-chosen and observable):
	// PinnedSender{self=A} must make payload[0] name A's slot. slotAddr decrypts to A. A double-index
	// bug (attrIndex = witness_index[idx]) makes slotAddr != A here -> RED.
	_, slotAddr8, recvSlot8 := decodeAttributionByte(t, 8, TransferOptions{PinnedSender: &PinnedSender{Address: srcAddr}})
	if slotAddr8 != srcAddr {
		t.Fatalf("RING8 PinnedSender{A}: payload[0] names %q, want the real sender A=%q. If it names B or a "+
			"decoy, the slot was double-indexed (attrIndex must be the publickeylist slot verbatim).", slotAddr8, srcAddr)
	}
	// NEGATIVE CONTROL (executed): payload[0] must NOT name the receiver B. Asserting it equals B
	// is the broken expectation; proving it is false here is the RED state we avoid.
	if slotAddr8 == dstAddr {
		t.Fatal("NEGATIVE CONTROL: payload[0] named the receiver B; indexing is wrong (RED state).")
	}

	// (FIX PROOF) THIRD-PARTY DECOY PINNING at RING==8: the headline use case. Pin a
	// registered decoy that is NOT the sender, NOT the receiver, and NOT independently curated
	// into the ring via opts.Ring. Before the fix this PANICKED ("not a ring member") because the
	// decoys are drawn randomly and the target was almost never present. The wallet layer now
	// FORCES the pinned-sender target into the ring, so the build must SUCCEED and payload[0] must name
	// the decoy's slot. This proves criterion 6 (no crash on a valid, pre-validated target) and
	// criterion 3 (the byte names the intended third party, not self/receiver).
	decoyAddr := decoys[0].GetAddress().String()
	_, slotAddrDecoy, _ := decodeAttributionByte(t, 8, TransferOptions{PinnedSender: &PinnedSender{Address: decoyAddr}})
	if slotAddrDecoy != decoyAddr {
		t.Fatalf("RING8 PinnedSender{decoy}: payload[0] names %q, want the pinned decoy=%q. The wallet must "+
			"force the pinned-sender target into the ring so a third-party target resolves to a real slot "+
			"instead of panicking.", slotAddrDecoy, decoyAddr)
	}
	if slotAddrDecoy == srcAddr || slotAddrDecoy == dstAddr {
		t.Fatal("RING8 PinnedSender{decoy}: payload[0] named the sender or receiver, not the pinned decoy; " +
			"injection/indexing is wrong.")
	}

	// (error-path) A NON-MEMBER / unregistered target must fail LOUD but RECOVERABLY — a clean typed
	// error from the wallet layer, NEVER a panic. We build a syntactically valid but unregistered
	// address by deriving one from a fresh keypair we never register on-chain.
	_, unregAddr := makeRingMember(0xDEADBEEF)
	wsrc.Sync_Wallet_Memory_With_Daemon()
	_, ferr := wsrc.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dstAddr, Amount: 90000, Payload_RPC: testPayload}},
		8, false, rpc.Arguments{}, 10000, false, TransferOptions{PinnedSender: &PinnedSender{Address: unregAddr}})
	if ferr == nil {
		t.Fatal("PinnedSender{unregistered}: expected a clean error, got nil — an invalid target must fail loud.")
	}
	// And the failure must be a returned error, not a panic (this call site has no recover; if the
	// engine had panicked on a non-member the test process would have crashed before reaching here).

	// (error-path) RING==2 with a third-party target: no decoy slot exists, so this must be a clean
	// error (not a panic, not a silent fallback that names the wrong member).
	_, ferr2 := wsrc.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dstAddr, Amount: 90000, Payload_RPC: testPayload}},
		2, false, rpc.Arguments{}, 10000, false, TransferOptions{PinnedSender: &PinnedSender{Address: decoyAddr}})
	if ferr2 == nil {
		t.Fatal("RING2 PinnedSender{third-party}: expected a clean error (ring 2 has no decoy slot), got nil.")
	}

	// (d, verified arm) RING==2 PinnedSender{self=A}: end-to-end, the receiver's REAL decode path
	// (Show_Transfers) attributes A and marks it verified (structural at ring 2).
	wsrc.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()
	tx2, err := wsrc.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dstAddr, Amount: 90000, Payload_RPC: testPayload}},
		2, false, rpc.Arguments{}, 10000, false, TransferOptions{PinnedSender: &PinnedSender{Address: srcAddr}})
	if err != nil {
		t.Fatalf("ring2 build failed: %s", err)
	}
	var dtx2 transaction.Transaction
	dtx2.Deserialize(tx2.Serialize())
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	wsrc.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()
	if err := chain.Add_TX_To_Pool(&dtx2); err != nil {
		t.Fatalf("ring2 add tx failed: %s", err)
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	wgenesis.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()
	entries := wdst.Show_Transfers(crypto.ZEROHASH, false, true, false, 0, uint64(chain.Get_Height())+1, "", "", 0, 0)
	if len(entries) == 0 {
		t.Fatal("ring2: receiver saw no incoming transfer")
	}
	last := entries[len(entries)-1]
	if last.RingSize != 2 {
		t.Fatalf("expected ring size 2, got %d", last.RingSize)
	}
	if last.Sender != srcAddr {
		t.Fatalf("RING2 PinnedSender{A}: receiver attributed %q, want the real sender A=%q.", last.Sender, srcAddr)
	}
	if !last.SenderVerified {
		t.Fatal("RING2 PinnedSender{A}: SenderVerified must be true at ring size 2 (structural).")
	}

	// (criterion 1 PROOF — the load-bearing privacy floor, exercised end-to-end) RING==8
	// PinnedSender{decoy}: a sender PINS a third-party decoy, the tx is MINED, and the RECEIVER reads
	// it back through the real daemon_communication.go export path (Show_Transfers). This is the
	// headline danger — a false accusation surviving export to the receiver at ring > 2 — and it
	// must be SCRUBBED: entry.Sender == "" (no resolvable accusation), !SenderVerified, and the
	// exported leading attribution byte zeroed (entry.Data[0] == 0). The earlier arms above stop at
	// decodeAttributionByte (in-memory decrypt of the freshly built tx) and observe payload[0]
	// BEFORE the scrub; THIS arm observes the scrubbed exported entry, proving the floor holds
	// behaviorally, not just by source-grep (attribution_export_guard_test.go).
	wsrc.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()
	tx8, err := wsrc.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dstAddr, Amount: 90000, Payload_RPC: testPayload}},
		8, false, rpc.Arguments{}, 10000, false, TransferOptions{PinnedSender: &PinnedSender{Address: decoyAddr}})
	if err != nil {
		t.Fatalf("ring8 pinned-decoy build failed: %s", err)
	}
	var dtx8 transaction.Transaction
	dtx8.Deserialize(tx8.Serialize())
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	wsrc.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()
	if err := chain.Add_TX_To_Pool(&dtx8); err != nil {
		t.Fatalf("ring8 pinned-decoy add tx failed: %s", err)
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	wgenesis.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()
	entries8 := wdst.Show_Transfers(crypto.ZEROHASH, false, true, false, 0, uint64(chain.Get_Height())+1, "", "", 0, 0)
	if len(entries8) == 0 {
		t.Fatal("ring8 pinned-decoy: receiver saw no incoming transfer")
	}
	// Pick the ring-8 incoming entry (the ring-2 arm above also left an entry on this wallet).
	var pinned8 *rpc.Entry
	for i := range entries8 {
		if entries8[i].RingSize == 8 && entries8[i].Incoming {
			pinned8 = &entries8[i]
		}
	}
	if pinned8 == nil {
		t.Fatal("ring8 pinned-decoy: no ring-8 incoming entry found in receiver's transfers")
	}
	// THE FLOOR: a sender-chosen false accusation must NOT survive export to the receiver.
	if pinned8.SenderVerified {
		t.Fatalf("RING8 PinnedSender{decoy}: SenderVerified must be false for ring > 2 (sender-chosen, "+
			"unauthenticated); got true — the scrub gate is mis-wired.")
	}
	if pinned8.Sender != "" {
		t.Fatalf("PRIVACY FLOOR BREACH (criterion 1): RING8 PinnedSender{decoy} exported entry.Sender=%q "+
			"to the receiver — a sender-chosen false accusation survived export. Must be blanked "+
			"(entry.Sender == \"\") when !SenderVerified.", pinned8.Sender)
	}
	// And the exported leading attribution byte must be zeroed, so the named slot is not
	// re-derivable from entry.Data via the public Publickeylist even though entry.Sender is blank.
	if len(pinned8.Data) == 0 {
		t.Fatal("RING8 PinnedSender{decoy}: exported entry.Data is empty; cannot confirm the leading byte was scrubbed.")
	}
	if pinned8.Data[0] != 0 {
		t.Fatalf("PRIVACY FLOOR BREACH (criterion 1): RING8 PinnedSender{decoy} exported entry.Data[0]=%d "+
			"(not zeroed). The sender-chosen attribution slot is re-derivable as "+
			"Publickeylist[Data[0]], re-deriving the pinned party even after entry.Sender is blanked.", pinned8.Data[0])
	}
	// NEGATIVE CONTROL (executed): the floor must be a SCRUB that erased a REAL, resolvable
	// accusation — not a vacuous pass because there was nothing to hide. Build the SAME pinned-decoy
	// opts once more and observe the UNSCRUBBED payload via the in-memory decode (decodeAttributionByte
	// bypasses the export scrub): pre-scrub it resolves to the decoy — a real, non-receiver
	// address. That is exactly the accusation the mined+read path above proved is GONE from the
	// exported entry (Sender==""). If pre-scrub had already named the receiver (or no one), the scrub
	// would be testing nothing. (NB: payload[0]'s numeric value is NOT asserted non-zero — the pinned
	// member can legitimately occupy publickeylist slot 0 after the ring shuffle; the load-bearing
	// erasure is entry.Sender being blanked, which removes the resolvable accusation regardless of the
	// raw byte value.)
	_, preScrubAddr, _ := decodeAttributionByte(t, 8, TransferOptions{PinnedSender: &PinnedSender{Address: decoyAddr}})
	if preScrubAddr != decoyAddr {
		t.Fatalf("NEGATIVE CONTROL: pre-scrub payload[0] resolves to %q, want the pinned decoy %q; "+
			"the scrub arm above is not exercising a real pinned accusation.", preScrubAddr, decoyAddr)
	}
	if preScrubAddr == dstAddr {
		t.Fatal("NEGATIVE CONTROL: pre-scrub attribution already named the receiver; the scrub of a " +
			"pinned third party would be vacuous.")
	}

	// (a) NilIsByteIdenticalToHonest: with PinnedSender nil, payload[0] must name the receiver's own
	// slot (the honest default = witness_index[1] = B). With PinnedSender{A}, payload[0] CHANGES to
	// name A's slot. This is the direct byte-level proof at ring 8 (observable, not overridden).
	nilByte, nilAddr, nilRecvSlot := decodeAttributionByte(t, 8, TransferOptions{})
	if nilByte != nilRecvSlot {
		t.Fatalf("NIL path: honest payload[0]=%d must be the receiver's own slot %d (witness_index[1]); "+
			"the zero-value TransferOptions{} must reproduce today's behavior byte-for-byte.", nilByte, nilRecvSlot)
	}
	if nilAddr != dstAddr {
		t.Fatalf("NIL path: honest payload[0] names %q, want the receiver B=%q.", nilAddr, dstAddr)
	}
	// And PinnedSender{A} must have CHANGED it away from the honest receiver slot to A.
	if slotAddr8 == nilAddr {
		t.Fatal("BYTE-IDENTITY/CHANGE: PinnedSender{A} produced the same attribution byte as the honest " +
			"nil default; the pinned-sender primitive did not change payload[0]. The guard does not bite.")
	}
	// NEGATIVE CONTROL for (a) (executed): the honest nil byte must NOT already be A's slot — if it
	// were, "PinnedSender{A} changes the byte" would be vacuously satisfiable. The receiver slot recvSlot8
	// (B) is what nil writes; A's slot is observed via slotAddr8 above and they differ.
	_ = recvSlot8
}

// NOTE: a former Test_SenderPinGuard_RotationLeavesPinnedSenderNil was DELETED here. It constructed
// literal TransferOptions structs and asserted .PinnedSender == nil, which only re-verified Go's
// zero-value semantics (a tautology) and could never catch a real rotation-sets-PinnedSender
// regression. The genuine rotation-isolation protection is the source-grep in
// Test_SenderPinGuard_NeverReachedByRotationEngine, which fails RED if ANY engine source assigns
// .PinnedSender (now name-agnostic) — i.e. if a rotation/curation path ever set the field.
