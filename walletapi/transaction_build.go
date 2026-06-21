package walletapi

import (
	"fmt"
	"math/big"
	"strconv"

	//import "encoding/binary"
	mathrand "math/rand"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// this is run some tests and benchmarks
type GenerateProofFunc func(scid crypto.Hash, scid_index int, s *crypto.Statement, witness *crypto.Witness, u *bn256.G1, txid crypto.Hash, burn_value uint64) *crypto.Proof

var GenerateProoffuncptr GenerateProofFunc = crypto.GenerateProof

// AttributionMode controls which ring slot index is written into the encrypted
// receiver payload (the leading byte at the witness_index write below). It changes
// only the sender-attribution metadata the receiver decrypts; it never affects which
// keys are sender/receiver, the amount, the recipient, or consensus validity.
type AttributionMode uint8

const (
	// AttributionHonest writes witness_index[1] (the receiver's own slot) — the default
	// and today's behavior. The receiver already knows it is the receiver, so this leaks
	// nothing about the sender.
	//
	// GUARDRAIL: honest mode MUST write witness_index[1] and MUST NOT be changed to
	// witness_index[0] (the real sender slot). Writing the sender slot would make the
	// receiver-decryptable byte reveal the true sender on every transfer.
	AttributionHonest AttributionMode = iota
	// AttributionAnonymous writes the slot index of a decoy ring member (drawn from the
	// anonymity set, never the real sender or receiver). The receiver is reduced to the
	// ring's 1-of-N anonymity instead of being handed the sender's slot directly.
	AttributionAnonymous
	// A "point attribution at a specific named address" mode is intentionally NOT defined:
	// that is targeted impersonation, not privacy.
)

// RingPreference is an opt-in decoy-curation hint for ring assembly. A nil
// *RingPreference reproduces today's behavior (pure DERO.GetRandomAddress selection).
// The curation logic that consumes it is wired in wallet_transfer.go.
type RingPreference struct {
	// PreferredDecoys are base-address strings to place in the ring first (after dedup);
	// random members top up to ringsize. Each is validated registered on the base balance
	// tree before use. Addresses the user controls must NOT be supplied here — curating
	// your own addresses collapses your anonymity set.
	PreferredDecoys []string
	// Strict: if true, a bad preferred decoy (unparseable / self / duplicate / unregistered)
	// is a hard error. If false (default), it is skipped and random selection fills the slot.
	Strict bool
}

// PinnedSender is an opt-in, additive primitive that lets the sender deliberately
// name WHICH ring slot the receiver-decryptable attribution byte points at. The engine
// exposes only the mechanism: it resolves Address to its publickeylist slot and writes
// that slot. ALL policy (which member, when, with what disclosure) lives in the
// wallet layer. A nil *PinnedSender reproduces today's behavior exactly.
//
// Safety: this is gated by the same export scrub as every other unverified
// attribution (ring > 2): entry.Sender is blanked and the leading slot byte is zeroed
// in the exported copy, so a sender-chosen attribution cannot be republished as a
// verified accusation. Resolution is purely mechanical — the only rejection is "the
// address is not a member of this ring" (no slot exists for it).
type PinnedSender struct {
	// Address is the base address whose ring slot the attribution byte should name.
	// Any ring member is valid (self, receiver, or any decoy). A non-member is a hard
	// build error; there is no silent fallback.
	Address string
}

// TransferOptions carries opt-in, additive transfer privacy knobs. The zero value
// reproduces today's behavior exactly (honest attribution, random ring selection).
type TransferOptions struct {
	Attribution AttributionMode // zero value = AttributionHonest
	Ring        *RingPreference // nil = today's random ring selection
	// PinnedSender is an opt-in primitive: when non-nil, the sender-attribution byte
	// names the ring slot of PinnedSender.Address (any ring member). nil = off (today's
	// behavior). It is a SEPARATE field, not a third AttributionMode, so the attribution-
	// rotation engine that drives the enum is structurally unable to reach it.
	PinnedSender *PinnedSender
}

// resolvePinnedSenderIndex returns the PUBLICKEYLIST SLOT index whose key matches the
// pinned-sender address. The decode side reads payload[0] DIRECTLY as
// Publickeylist[payload[0]] (daemon_communication.go), so the returned value is the
// byte written verbatim — it must NOT be re-indexed through witness_index.
//
// Resolution is purely mechanical: any ring member is a valid target. The only failures
// are an unparseable address or one that is not a member of this ring (no slot exists
// for it). There is no policy filter and no silent fallback.
func resolvePinnedSenderIndex(pin *PinnedSender, publickeylist []*bn256.G1) (int, error) {
	addr, err := rpc.NewAddress(pin.Address)
	if err != nil {
		return 0, fmt.Errorf("pinned sender not a valid address: %s", pin.Address)
	}
	targetKey := addr.PublicKey.G1()
	for idx, member := range publickeylist {
		if member.String() == targetKey.String() {
			return idx, nil
		}
	}
	return 0, fmt.Errorf("pinned sender is not a ring member: %s", pin.Address)
}

// generate proof  etc
//
// BuildTransaction is preserved verbatim as a shim over buildTransaction so existing
// callers (tests, benchmarks) keep compiling and get honest, non-curated behavior.
func (w *Wallet_Memory) BuildTransaction(transfers []rpc.Transfer, emap [][][]byte, rings [][]*bn256.G1, block_hash crypto.Hash, height uint64, scdata rpc.Arguments, roothash []byte, max_bits int, fees uint64) *transaction.Transaction {
	return w.buildTransaction(transfers, emap, rings, block_hash, height, scdata, roothash, max_bits, fees, TransferOptions{})
}

func (w *Wallet_Memory) buildTransaction(transfers []rpc.Transfer, emap [][][]byte, rings [][]*bn256.G1, block_hash crypto.Hash, height uint64, scdata rpc.Arguments, roothash []byte, max_bits int, fees uint64, opts TransferOptions) *transaction.Transaction {

	sender := w.account.Keys.Public.G1()
	sender_secret := w.account.Keys.Secret.BigInt()

	var retry_count int

rebuild_tx:

	var tx transaction.Transaction

	tx.Version = 1
	tx.Height = height
	tx.BLID = block_hash
	tx.TransactionType = transaction.NORMAL

	if len(scdata) >= 1 {
		tx.TransactionType = transaction.SC_TX
		tx.SCDATA = scdata
	}

	crand := mathrand.New(globals.NewCryptoRandSource())

	var witness_list []crypto.Witness

	umap := map[string][]byte{}

	fees_done := false

	if retry_count%len(rings[0]) == 0 {
		max_bits += 3
	}

	if max_bits >= 240 {
		panic("currently we cannot use more than 240 bits")
	}

	for t, _ := range transfers {

		var publickeylist, C, CLn, CRn []*bn256.G1
		var D bn256.G1

		receiver_addr, _ := rpc.NewAddress(transfers[t].Destination)
		receiver := receiver_addr.PublicKey.G1()

		var witness_index []int
		for i := 0; i < len(rings[t]); i++ { // todocheck whether this is power of 2 or not
			witness_index = append(witness_index, i)
		}

		for ; max_bits%8 != 0; max_bits++ { // round to next higher byte size
		}

		//witness_index[3], witness_index[1] = witness_index[1], witness_index[3]
		for {
			crand.Shuffle(len(witness_index), func(i, j int) {
				witness_index[i], witness_index[j] = witness_index[j], witness_index[i]
			})

			// make sure sender and receiver are not both odd or both even
			// sender will always be at  witness_index[0] and receiver will always be at witness_index[1]
			if witness_index[0]%2 != witness_index[1]%2 {
				break
			}
		}

		// Lots of ToDo for this, enables satisfying lots of  other things
		anonset_publickeys := rings[t][2:]
		anonset_balances := emap[t][2:]
		ebalances_list := make([]*crypto.ElGamal, 0, len(rings[t]))
		for i := range witness_index {
			switch i {
			case witness_index[0]:
				publickeylist = append(publickeylist, sender)
				ebalances_list = append(ebalances_list, new(crypto.ElGamal).Deserialize(emap[t][0]))
			case witness_index[1]:
				publickeylist = append(publickeylist, receiver)
				ebalances_list = append(ebalances_list, new(crypto.ElGamal).Deserialize(emap[t][1]))
			default:
				publickeylist = append(publickeylist, anonset_publickeys[0])
				ebalances_list = append(ebalances_list, new(crypto.ElGamal).Deserialize(anonset_balances[0]))
				anonset_publickeys = anonset_publickeys[1:]
				anonset_balances = anonset_balances[1:]
			}

			// fmt.Printf("adding %d %s  (ring count %d) \n", i,publickeylist[i].String(), len(anonset_publickeys))
		}

		// use updated balances if possible
		for i := range publickeylist {
			if bal, ok := umap[transfers[t].SCID.String()+publickeylist[i].String()]; ok {
				ebalances_list[i] = new(crypto.ElGamal).Deserialize(bal)
			}
		}

		//  fmt.Printf("len of publickeylist  %d \n", len(publickeylist))

		//  revealing r will disclose the amount and the sender and receiver and separate anonymous ring members
		// calculate r deterministically, so its different every transaction, in emergency it can be given to other, and still will not allows key attacks
		rinputs := append([]byte{}, roothash[:]...)
		for i := range publickeylist {
			rinputs = append(rinputs, publickeylist[i].EncodeCompressed()...)
		}
		rencrypted := new(bn256.G1).ScalarMult(crypto.HashToPoint(crypto.HashtoNumber(append([]byte(crypto.PROTOCOL_CONSTANT), rinputs...))), sender_secret)
		r := crypto.ReducedHash(rencrypted.EncodeCompressed())

		//fmt.Printf("t %d building transfers %+v\n", t, transfers[t])
		//fmt.Printf("building t %d r  calculated %s\n", t, r.Text(16))

		var asset transaction.AssetPayload

		asset.SCID = transfers[t].SCID
		asset.BurnValue = transfers[t].Burn

		value := transfers[t].Amount
		burn_value := transfers[t].Burn
		if fees == 0 && asset.SCID.IsZero() && !fees_done {
			fees = fees + uint64(len(transfers)+2)*uint64((float64(config.FEE_PER_KB)*float64(float32(len(publickeylist)/16)+w.GetFeeMultiplier())))
			if data, err := scdata.MarshalBinary(); err != nil {
				panic(err)
			} else {
				fees = fees + (uint64(len(data))*15)/10
			}
			fees_done = true
		}

		for i := range publickeylist { // setup commitments
			var x bn256.G1
			switch {
			case i == witness_index[0]:

				if asset.SCID.IsZero() {
					x.ScalarMult(crypto.G, new(big.Int).SetInt64(0-int64(value)-int64(fees)-int64(burn_value))) // decrease senders balance
				} else {
					x.ScalarMult(crypto.G, new(big.Int).SetInt64(0-int64(value)-int64(burn_value))) // decrease senders balance
				}
				//fmt.Printf("sender %d %s \n", i, sender.String())

			case i == witness_index[1]:
				x.ScalarMult(crypto.G, new(big.Int).SetInt64(int64(value))) // increase receiver's balance
				//fmt.Printf("receiver %d %s \n",i, receiver.String())

				// lets encrypt the payment id, it's simple, we XOR the paymentID
				//blinder := new(bn256.G1).ScalarMult(publickeylist[i], r)

				// we must obfuscate it for non-client call, actual limit is 128, but for future testing/support
				if len(publickeylist) >= 512 {
					panic("currently we donot support ring size >= 512")
				}

				asset.RPCType = transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2

				data, _ := transfers[t].Payload_RPC.CheckPack(transaction.PAYLOAD0_LIMIT)

				ephemeral_key := crypto.ShakeXOF(publickeylist[i].String(), sender_secret.Bytes(), roothash[:])
				ephemeral_seed := crypto.ShakeXOF(sender.String(), ephemeral_key[:], rinputs, publickeylist[i].EncodeCompressed())
				ephemeral_scalar := new(big.Int).SetBytes(ephemeral_seed[:])
				ephemeral_scalar = ephemeral_scalar.Mod(ephemeral_scalar, bn256.Order)
				ephemeral_pub := crypto.GPoint.ScalarMult(crypto.GetBNRed(ephemeral_scalar))

				shared_key := crypto.GenerateSharedSecret(ephemeral_scalar, publickeylist[i])

				// honest attribution writes witness_index[1] (the receiver's own slot).
				// GUARDRAIL: never witness_index[0] (the real sender) — that would reveal
				// the true sender to the receiver on every transfer.
				attrIndex := witness_index[1]
				if opts.Attribution == AttributionAnonymous && len(witness_index) > 2 {
					// witness_index[2:] are the anonymity-set (decoy) slots: real, registered
					// ring members that are neither the sender [0] nor the receiver [1].
					// Pointing attribution at one reduces the receiver to 1-of-N ring anonymity.
					decoyPos := 2 + crand.Intn(len(witness_index)-2)
					attrIndex = witness_index[decoyPos]
				}
				// Pinned-sender primitive (opt-in, nil = off): when set, the sender deliberately
				// names which ring slot the attribution byte points at. resolvePinnedSenderIndex
				// returns a PUBLICKEYLIST SLOT, and the decode side reads payload[0] DIRECTLY
				// as Publickeylist[payload[0]] — so write the slot verbatim. Do NOT wrap it in
				// witness_index[]; that would double-index and name the wrong ring member.
				//
				// The wallet layer (TransferPayload0WithOptions) pre-validates the target and
				// FORCES it into the ring, so for any caller using that entrypoint the target
				// is a guaranteed member and resolvePinnedSenderIndex cannot fail. The panic below
				// is therefore a can't-happen invariant guard (defense in depth for a direct
				// buildTransaction caller that skipped wallet validation), matching the other
				// invariant panics in this function (max_bits, ring>=512) — NOT input
				// validation. Routine input errors are returned cleanly by the wallet layer.
				if opts.PinnedSender != nil {
					idx, err := resolvePinnedSenderIndex(opts.PinnedSender, publickeylist)
					if err != nil {
						panic(err)
					}
					attrIndex = idx
				}
				payload := append([]byte{byte(uint(attrIndex))}, data...)
				//fmt.Printf("buulding shared_key %x  index of receiver %d\n",shared_key,i)
				//fmt.Printf("building plaintext payload %x\n",asset.RPCPayload)

				//fmt.Printf("%d packed rpc payload %d %x\n ", t, len(data), data)
				// make sure used data encryption is optional, just in case we would like to play together with ring members
				// we intoduce an element to create dependency of input key, so receiver cannot prove otherwise
				crypto.EncryptDecryptUserData(crypto.Keccak256(shared_key[:], publickeylist[i].EncodeCompressed()), payload)
				asset.RPCPayload = append(ephemeral_pub.EncodeCompressed(), payload...)

				//fmt.Printf("building encrypted payload %x\n",asset.RPCPayload)

			default:
				x.ScalarMult(crypto.G, new(big.Int).SetInt64(0))
			}

			x.Add(new(bn256.G1).Set(&x), new(bn256.G1).ScalarMult(publickeylist[i], r)) // hide all commitments behind r
			C = append(C, &x)
		}
		D.ScalarMult(crypto.G, r)

		for i := range publickeylist {
			ebalance := ebalances_list[i]

			var ll, rr bn256.G1
			//ebalance := b.balances[publickeylist[i].String()] // note these are taken from the chain live

			ll.Add(ebalance.Left, C[i])
			CLn = append(CLn, &ll)
			//  fmt.Printf("%d CLnG %x\n", i,CLn[i].EncodeCompressed())

			rr.Add(ebalance.Right, &D)
			CRn = append(CRn, &rr)
			//  fmt.Printf("%d CRnG %x\n",i, CRn[i].EncodeCompressed())

		}

		// decode sender (our) balance now, it might have been updated
		balance := w.DecodeEncryptedBalanceNow(ebalances_list[witness_index[0]])

		//fmt.Printf("t %d scid %s  balance %d\n", t, transfers[t].SCID, balance)

		// time for bullets-sigma
		fees_currentasset := uint64(0)
		if asset.SCID.IsZero() {
			fees_currentasset = fees
		}
		statement := GenerateStatement(CLn, CRn, publickeylist, C, &D, fees_currentasset) // generate statement

		copy(statement.Roothash[:], roothash[:])
		statement.Bytes_per_publickey = byte(max_bits / 8)

		witness := GenerateWitness(sender_secret, r, value, balance-value-fees_currentasset-burn_value, witness_index)

		witness_list = append(witness_list, witness)

		// this goes to proof.u

		//Print(statement, witness)
		asset.Statement = statement

		tx.Payloads = append(tx.Payloads, asset)

		// get ready for another round by internal processing of state

		for i := range publickeylist {
			balance := ebalances_list[i]
			echanges := crypto.ConstructElGamal(statement.C[i], statement.D)
			balance = balance.Add(echanges)                                                  // homomorphic addition of changes
			umap[transfers[t].SCID.String()+publickeylist[i].String()] = balance.Serialize() // reserialize and store
		}

	}

	scid_map := map[crypto.Hash]int{}
	for t := range transfers {
		// the u is dependent on roothash,SCID and counter ( counter is dynamic and depends on order of assets)

		uinput := append([]byte(crypto.PROTOCOL_CONSTANT), tx.Payloads[t].Statement.Roothash[:]...)
		scid_index := scid_map[tx.Payloads[t].SCID]
		scid_index_str := strconv.Itoa(scid_index)
		uinput = append(uinput, tx.Payloads[t].SCID[:]...)
		uinput = append(uinput, scid_index_str...)

		u := new(bn256.G1).ScalarMult(crypto.HashToPoint(crypto.HashtoNumber(uinput)), sender_secret) // this should be moved to generate proof

		scid_map[tx.Payloads[t].SCID] = scid_map[tx.Payloads[t].SCID] + 1

		//tx.Payloads[t].Proof = crypto.GenerateProof(&tx.Payloads[t].Statement, &witness_list[t], u, tx.GetHash(), tx.Payloads[t].BurnValue)

		tx.Payloads[t].Proof = GenerateProoffuncptr(tx.Payloads[t].SCID, scid_index, &tx.Payloads[t].Statement, &witness_list[t], u, tx.GetHash(), tx.Payloads[t].BurnValue)

	}

	// after the tx is serialized, it loses information which is then fed by blockchain

	scid_map_t := map[crypto.Hash]int{}
	for t := range tx.Payloads {
		if tx.Payloads[t].Proof.Verify(tx.Payloads[t].SCID, scid_map_t[tx.Payloads[t].SCID], &tx.Payloads[t].Statement, tx.GetHash(), tx.Payloads[t].BurnValue) {
			//fmt.Printf("TX verified with proof successfuly %s  burn_value %d\n", tx.GetHash(), tx.Payloads[t].BurnValue)
		} else {
			fmt.Printf("TX verification failed, did u try sending more than you have !!!!!!!!!!\n")
			return nil
		}
		scid_map_t[tx.Payloads[t].SCID] = scid_map_t[tx.Payloads[t].SCID] + 1
	}

	if tx.TransactionType == transaction.SC_TX {
		if tx.SCDATA.Has(rpc.SCACTION, rpc.DataUint64) {
			if rpc.SC_INSTALL == rpc.SC_ACTION(tx.SCDATA.Value(rpc.SCACTION, rpc.DataUint64).(uint64)) {
				txid := tx.GetHash()
				if txid[0] < 0x80 || txid[31] < 0x80 { // last byte should be more than 0x80
					if retry_count <= 20 {
						//fmt.Printf("rebuilding tx %s retry_count %d\n", txid, retry_count)
						goto rebuild_tx
					}
				}
			}
		}
	}

	// these 2 steps are only necessary, since blockchain doesn't accept unserialized txs
	//var dtx transaction.Transaction
	//_ = dtx.DeserializeHeader(tx.Serialize())

	return &tx
}

// generate statement
func GenerateStatement(CLn, CRn, publickeylist, C []*bn256.G1, D *bn256.G1, fees uint64) crypto.Statement {
	return crypto.Statement{CLn: CLn, CRn: CRn, Publickeylist: publickeylist, C: C, D: D, Fees: fees}
}

// generate witness
func GenerateWitness(secretkey, r *big.Int, TransferAmount, Balance uint64, index []int) crypto.Witness {
	return crypto.Witness{SecretKey: secretkey, R: r, TransferAmount: TransferAmount, Balance: Balance, Index: index}
}
