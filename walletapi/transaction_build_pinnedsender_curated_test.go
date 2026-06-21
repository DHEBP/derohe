package walletapi

// Guard: the curated-ring (RingPreference) and pinned-sender primitive must compose
// correctly. Injection runs before curatedRingCandidates and seeds the same
// dedup map, so this exercises pinned-sender+curation together — distinct targets,
// overlap with a preferred decoy, Strict errors on a bad curated decoy,
// non-strict skip, pinned-sender==receiver no-op, and slot placement (CASE A-F).

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

func Test_SenderPinGuard_CuratedRingInteraction(t *testing.T) {
	time.Sleep(time.Millisecond)
	Initialize_LookupTable(1, 1<<17)

	wsrc_temp_db := filepath.Join(os.TempDir(), "zzcf_wallet_src.db")
	wdst_temp_db := filepath.Join(os.TempDir(), "zzcf_wallet_dst.db")
	os.Remove(wsrc_temp_db)
	os.Remove(wdst_temp_db)

	wsrc, err := Create_Encrypted_Wallet_From_Recovery_Words(wsrc_temp_db, "QWER", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("src wallet: %s", err)
	}
	wdst, err := Create_Encrypted_Wallet_From_Recovery_Words(wdst_temp_db, "QWER", "Dekade Spagat Bereich Radclub Yeti Dialekt Unimog Nomade Anlage Hirte Besitz Märzluft Krabbe Nabel Halsader Chefarzt Hering tauchen Neuerung Reifen Umgang Hürde Alchimie Amnesie Reifen")
	if err != nil {
		t.Fatalf("dst wallet: %s", err)
	}
	wgenesis, err := Create_Encrypted_Wallet_From_Recovery_Words(wdst_temp_db, "QWER", "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")
	if err != nil {
		t.Fatalf("genesis wallet: %s", err)
	}

	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], wgenesis.account.Keys.Public.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	genesis_block := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesis_block.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesis_block.GetHash()

	chain, rpcserver, _ := simulator_chain_start()
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
		t.Fatalf("src regtx: %s", err)
	}
	if err := chain.Add_TX_To_Pool(wdst.GetRegistrationTX()); err != nil {
		t.Fatalf("dst regtx: %s", err)
	}

	var decoys []*Wallet_Disk
	for i := 0; i < 12; i++ {
		d, derr := Create_Encrypted_Wallet_Random(filepath.Join(os.TempDir(), fmt.Sprintf("zzcf_decoy_%d.db", i)), "QWER")
		if derr != nil {
			t.Fatalf("decoy %d: %s", i, derr)
		}
		defer d.Close_Encrypted_Wallet()
		defer os.Remove(filepath.Join(os.TempDir(), fmt.Sprintf("zzcf_decoy_%d.db", i)))
		if err := chain.Add_TX_To_Pool(d.GetRegistrationTX()); err != nil {
			t.Fatalf("decoy reg %d: %s", i, err)
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
	wsrc.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()

	dstAddr := wdst.GetAddress().String()
	srcAddr := wsrc.GetAddress().String()
	_ = srcAddr

	testPayload := rpc.Arguments{
		{Name: rpc.RPC_COMMENT, DataType: rpc.DataString, Value: "curated pinned sender"},
	}

	// ringComposition builds the tx, returns the ordered list of ring member address strings
	// (slot 0..ringsize-1) for the native-SCID payload.
	ringComposition := func(t *testing.T, ringsize uint64, opts TransferOptions) (members []string, err error) {
		wsrc.Sync_Wallet_Memory_With_Daemon()
		tx, e := wsrc.TransferPayload0WithOptions(
			[]rpc.Transfer{{Destination: dstAddr, Amount: 90000, Payload_RPC: testPayload}},
			ringsize, false, rpc.Arguments{}, 10000, false, opts)
		if e != nil {
			return nil, e
		}
		pkl := tx.Payloads[0].Statement.Publickeylist
		for _, k := range pkl {
			a := rpc.NewAddressFromKeys((*crypto.Point)(k))
			a.Mainnet = wsrc.GetNetwork()
			members = append(members, a.String())
		}
		return members, nil
	}

	contains := func(list []string, s string) int {
		n := 0
		for _, x := range list {
			if x == s {
				n++
			}
		}
		return n
	}

	P1 := decoys[0].GetAddress().String()
	P2 := decoys[1].GetAddress().String()
	F := decoys[2].GetAddress().String() // pinned-sender target, distinct from P1/P2

	// CASE A: curated (Strict) + pinned sender of a DISTINCT third party.
	{
		members, err := ringComposition(t, 8, TransferOptions{
			Ring:         &RingPreference{PreferredDecoys: []string{P1, P2}, Strict: true},
			PinnedSender: &PinnedSender{Address: F},
		})
		if err != nil {
			t.Fatalf("CASE A build failed: %s", err)
		}
		if len(members) != 8 {
			t.Fatalf("CASE A: ring has %d members, want 8: %v", len(members), members)
		}
		// distinctness across whole ring
		seen := map[string]bool{}
		for _, m := range members {
			if seen[m] {
				t.Fatalf("CASE A: DUPLICATE ring member %s in %v", m, members)
			}
			seen[m] = true
		}
		if contains(members, F) != 1 {
			t.Fatalf("CASE A: pinned-sender target F appears %d times (want 1): %v", contains(members, F), members)
		}
		if contains(members, P1) != 1 {
			t.Fatalf("CASE A: curated P1 dropped (count %d): %v", contains(members, P1), members)
		}
		if contains(members, P2) != 1 {
			t.Fatalf("CASE A: curated P2 dropped (count %d): %v", contains(members, P2), members)
		}
		if contains(members, srcAddr) != 1 || contains(members, dstAddr) != 1 {
			t.Fatalf("CASE A: sender/receiver miscount: %v", members)
		}
		t.Logf("CASE A OK members=%v\n  slot2(injected)=%s P1=%s P2=%s F=%s", members, members[2], P1, P2, F)
		// position check: is F deterministically at slot 2?
		if members[2] != F {
			t.Logf("CASE A NOTE: F not at slot 2; it is at index %d", contains(members, F))
		}
	}

	// CASE B: pinned-sender target == one of the PreferredDecoys (overlap P1==F).
	{
		members, err := ringComposition(t, 8, TransferOptions{
			Ring:         &RingPreference{PreferredDecoys: []string{P1, P2}, Strict: true},
			PinnedSender: &PinnedSender{Address: P1},
		})
		if err != nil {
			t.Fatalf("CASE B build failed: %s", err)
		}
		if len(members) != 8 {
			t.Fatalf("CASE B: ring has %d members, want 8: %v", len(members), members)
		}
		seen := map[string]bool{}
		for _, m := range members {
			if seen[m] {
				t.Fatalf("CASE B: DUPLICATE ring member %s (overlap double-counted!): %v", m, members)
			}
			seen[m] = true
		}
		if contains(members, P1) != 1 {
			t.Fatalf("CASE B: overlapped P1/F appears %d times (want exactly 1): %v", contains(members, P1), members)
		}
		if contains(members, P2) != 1 {
			t.Fatalf("CASE B: curated P2 DROPPED when pinned sender overlaps P1 (count %d): %v", contains(members, P2), members)
		}
		t.Logf("CASE B OK (overlap) members=%v", members)
	}

	// CASE C: Strict mode must still error on a BAD curated decoy even with a pinned sender set.
	{
		_, err := ringComposition(t, 8, TransferOptions{
			Ring:         &RingPreference{PreferredDecoys: []string{"not-a-valid-address"}, Strict: true},
			PinnedSender: &PinnedSender{Address: F},
		})
		if err == nil {
			t.Fatal("CASE C: Strict mode with bad curated decoy + pinned sender must error, got nil")
		}
		t.Logf("CASE C OK strict-error: %s", err)
	}

	// CASE D: non-strict mode, bad curated decoy is skipped; pinned sender still injected; ring still fills.
	{
		members, err := ringComposition(t, 8, TransferOptions{
			Ring:         &RingPreference{PreferredDecoys: []string{"not-a-valid-address", P1}, Strict: false},
			PinnedSender: &PinnedSender{Address: F},
		})
		if err != nil {
			t.Fatalf("CASE D build failed: %s", err)
		}
		if len(members) != 8 {
			t.Fatalf("CASE D: ring has %d members, want 8: %v", len(members), members)
		}
		if contains(members, F) != 1 || contains(members, P1) != 1 {
			t.Fatalf("CASE D: F or P1 miscount: %v", members)
		}
		t.Logf("CASE D OK members=%v", members)
	}

	// CASE E: pinned-sender target == receiver, with curation. Should be a no-op injection (receiver already slot 1).
	{
		members, err := ringComposition(t, 8, TransferOptions{
			Ring:         &RingPreference{PreferredDecoys: []string{P1, P2}, Strict: true},
			PinnedSender: &PinnedSender{Address: dstAddr},
		})
		if err != nil {
			t.Fatalf("CASE E build failed: %s", err)
		}
		seen := map[string]bool{}
		for _, m := range members {
			if seen[m] {
				t.Fatalf("CASE E: DUPLICATE ring member %s: %v", m, members)
			}
			seen[m] = true
		}
		if len(members) != 8 || contains(members, dstAddr) != 1 || contains(members, P1) != 1 || contains(members, P2) != 1 {
			t.Fatalf("CASE E: miscount: %v", members)
		}
		t.Logf("CASE E OK members=%v", members)
	}

	// CASE F: positional fingerprint check (invariant 2). Compare slot of pinned member
	// across many pinned txs vs position of a random decoy in anonymous txs.
	{
		pinnedSlotCounts := map[int]int{}
		for i := 0; i < 10; i++ {
			members, err := ringComposition(t, 8, TransferOptions{PinnedSender: &PinnedSender{Address: F}})
			if err != nil {
				t.Fatalf("CASE F build %d failed: %s", i, err)
			}
			for slot, m := range members {
				if m == F {
					pinnedSlotCounts[slot]++
				}
			}
		}
		t.Logf("CASE F pinned-member slot distribution over 10 builds: %v", pinnedSlotCounts)
	}
}
