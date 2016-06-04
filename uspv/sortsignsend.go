package uspv

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"sort"

	"github.com/roasbeef/btcd/blockchain"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/btcutil/bloom"
	"github.com/roasbeef/btcutil/txsort"
)

func (s *SPVCon) PongBack(nonce uint64) {
	mpong := wire.NewMsgPong(nonce)

	s.outMsgQueue <- mpong
	return
}

func (s *SPVCon) SendFilter(f *bloom.Filter) {
	s.outMsgQueue <- f.MsgFilterLoad()

	return
}

// Rebroadcast sends an inv message of all the unconfirmed txs the db is
// aware of.  This is called after every sync.  Only txids so hopefully not
// too annoying for nodes.
func (s *SPVCon) Rebroadcast() {
	// get all unconfirmed txs
	invMsg, err := s.TS.GetPendingInv()
	if err != nil {
		log.Printf("Rebroadcast error: %s", err.Error())
	}
	if len(invMsg.InvList) == 0 { // nothing to broadcast, so don't
		return
	}
	s.outMsgQueue <- invMsg
	return
}

// make utxo slices sortable -- same as txsort
type utxoSlice []Utxo

// Sort utxos just like txins -- Len, Less, Swap
func (s utxoSlice) Len() int      { return len(s) }
func (s utxoSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// outpoint sort; First input hash (reversed / rpc-style), then index.
func (s utxoSlice) Less(i, j int) bool {
	// Input hashes are the same, so compare the index.
	ihash := s[i].Op.Hash
	jhash := s[j].Op.Hash
	if ihash == jhash {
		return s[i].Op.Index < s[j].Op.Index
	}
	// At this point, the hashes are not equal, so reverse them to
	// big-endian and return the result of the comparison.
	const hashSize = wire.HashSize
	for b := 0; b < hashSize/2; b++ {
		ihash[b], ihash[hashSize-1-b] = ihash[hashSize-1-b], ihash[b]
		jhash[b], jhash[hashSize-1-b] = jhash[hashSize-1-b], jhash[b]
	}
	return bytes.Compare(ihash[:], jhash[:]) == -1
}

type SortableUtxoSlice []*Utxo

// utxoByAmts get sorted by utxo value. also put unconfirmed last
func (s SortableUtxoSlice) Len() int      { return len(s) }
func (s SortableUtxoSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// height 0 means your lesser
func (s SortableUtxoSlice) Less(i, j int) bool {
	if s[i].AtHeight == 0 && s[j].AtHeight > 0 {
		return true
	}
	if s[j].AtHeight == 0 && s[i].AtHeight > 0 {
		return false
	}
	return s[i].Value < s[j].Value
}

// NewOutgoingTx runs a tx though the db first, then sends it out to the network.
func (s *SPVCon) NewOutgoingTx(tx *wire.MsgTx) error {
	txid := tx.TxSha()
	// assign height of zero for txs we create
	err := s.TS.AddTxid(&txid, 0)
	if err != nil {
		return err
	}
	_, err = s.TS.Ingest(tx, 0) // our own tx; don't keep track of false positives
	if err != nil {
		return err
	}
	// make an inv message instead of a tx message to be polite
	iv1 := wire.NewInvVect(wire.InvTypeWitnessTx, &txid)
	invMsg := wire.NewMsgInv()
	err = invMsg.AddInvVect(iv1)
	if err != nil {
		return err
	}
	s.outMsgQueue <- invMsg
	return nil
}

// PickUtxos Picks Utxos for spending.  Tell it how much money you want.
// It returns a tx-sortable utxoslice, and the overshoot amount.  Also errors.
// if "ow" is true, only gives witness utxos (for channel funding)
func (s *SPVCon) PickUtxos(amtWanted int64, ow bool) (utxoSlice, int64, error) {
	satPerByte := int64(80) // satoshis per byte fee; have as arg later
	curHeight, err := s.TS.GetDBSyncHeight()
	if err != nil {
		return nil, 0, err
	}

	var allUtxos SortableUtxoSlice
	allUtxos, err = s.TS.GetAllUtxos()
	if err != nil {
		return nil, 0, err
	}

	// start with utxos sorted by value.
	// smallest and unconfirmed last (because it's reversed)
	sort.Sort(sort.Reverse(allUtxos))

	var rSlice utxoSlice
	// add utxos until we've had enough
	nokori := amtWanted // nokori is how much is needed on input side
	for _, utxo := range allUtxos {
		// skip unconfirmed.  Or de-prioritize? Some option for this...
		//		if utxo.AtHeight == 0 {
		//			continue
		//		}
		if utxo.SpendLag > 1 &&
			(utxo.AtHeight < 100 || utxo.AtHeight+utxo.SpendLag > curHeight) {
			continue // skip immature or unconfirmed time-locked sh outputs
		}
		if ow && utxo.SpendLag == 0 {
			continue // skip non-witness
		}
		// why are 0-value outputs a thing..?
		if utxo.Value < 1 {
			continue
		}
		// yeah, lets add this utxo!
		rSlice = append(rSlice, *utxo)
		nokori -= utxo.Value
		// if nokori is positive, don't bother checking fee yet.
		if nokori < 0 {
			var byteSize int64
			for _, txo := range rSlice {
				if txo.SpendLag > 0 {
					byteSize += 70 // vsize of wit inputs is ~68ish
				} else {
					byteSize += 130 // vsize of non-wit input is ~130
				}
			}
			fee := byteSize * satPerByte
			if nokori < -fee { // done adding utxos: nokori below negative est fee
				break
			}
		}
	}
	if nokori > 0 {
		return nil, 0, fmt.Errorf("wanted %d but %d available.",
			amtWanted, amtWanted-nokori)
	}

	sort.Sort(rSlice) // send sorted.  This is probably redundant?
	return rSlice, -nokori, nil
}

// SendDrop sends 2 chained transactions; one to a 2drop script, and then
// one spending that to an address.
// Note that this is completely insecure for any purpose, and
// all it does is waste space.  Kindof useless.
// Returns the 2nd, large tx's txid.
// Probably doesn't work with time-locked.  Doesn't really matter.
func (s *SPVCon) SendDrop(u Utxo, adr btcutil.Address) (*wire.ShaHash, error) {
	var err error
	// fixed fee
	fee := int64(5000)

	sendAmt := u.Value - fee
	tx := wire.NewMsgTx() // make new tx

	// add single dropdrop output
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_2DROP)
	builder.AddOp(txscript.OP_2DROP)
	builder.AddOp(txscript.OP_2DROP)
	builder.AddOp(txscript.OP_2DROP)
	builder.AddOp(txscript.OP_2DROP)
	builder.AddOp(txscript.OP_2DROP)
	builder.AddOp(txscript.OP_2DROP)
	builder.AddOp(txscript.OP_2DROP)
	builder.AddOp(txscript.OP_1)
	outpre, _ := builder.Script()

	txout := wire.NewTxOut(sendAmt, P2WSHify(outpre))
	tx.AddTxOut(txout)

	// build input
	var prevPKs []byte
	if u.SpendLag > 0 {
		//		tx.Flags = 0x01
		wa, err := btcutil.NewAddressWitnessPubKeyHash(
			s.TS.Adrs[u.KeyIdx].PkhAdr.ScriptAddress(), s.TS.Param)
		prevPKs, err = txscript.PayToAddrScript(wa)
		if err != nil {
			return nil, err
		}
	} else { // otherwise generate directly
		prevPKs, err = txscript.PayToAddrScript(
			s.TS.Adrs[u.KeyIdx].PkhAdr)
		if err != nil {
			return nil, err
		}
	}
	tx.AddTxIn(wire.NewTxIn(&u.Op, prevPKs, nil))

	var sig []byte
	var wit [][]byte
	hCache := txscript.NewTxSigHashes(tx)

	priv := s.TS.GetWalletPrivkey(u.KeyIdx)
	if priv == nil {
		return nil, fmt.Errorf("SendDrop: nil privkey")
	}

	// This is where witness based sighash types need to happen
	// sign into stash
	if u.SpendLag > 0 {
		wit, err = txscript.WitnessScript(
			tx, hCache, 0, u.Value, tx.TxIn[0].SignatureScript,
			txscript.SigHashAll, priv, true)
		if err != nil {
			return nil, err
		}
	} else {
		sig, err = txscript.SignatureScript(
			tx, 0, tx.TxIn[0].SignatureScript,
			txscript.SigHashAll, priv, true)
		if err != nil {
			return nil, err
		}
	}

	// swap sigs into sigScripts in txins
	if sig != nil {
		tx.TxIn[0].SignatureScript = sig
	}
	if wit != nil {
		tx.TxIn[0].Witness = wit
		tx.TxIn[0].SignatureScript = nil
	}
	err = s.NewOutgoingTx(tx)
	if err != nil {
		return nil, err
	}
	tx1id := tx.TxSha()
	sendAmt2 := sendAmt - fee
	tx2 := wire.NewMsgTx() // make new tx

	// now build a NEW tx spending that one!
	// add single output
	outAdrScript, err := txscript.PayToAddrScript(adr)
	if err != nil {
		return nil, err
	}

	txout2 := wire.NewTxOut(sendAmt2, outAdrScript)
	tx2.AddTxOut(txout2)

	dropIn := wire.NewTxIn(wire.NewOutPoint(&tx1id, 0), nil, nil)
	dropIn.Witness = make([][]byte, 17)

	for i, _ := range dropIn.Witness {
		dropIn.Witness[i] = make([]byte, 512)
		_, err := rand.Read(dropIn.Witness[i])
		if err != nil {
			return nil, err
		}
	}
	dropIn.Witness[16] = outpre
	tx2.AddTxIn(dropIn)
	txid := tx2.TxSha()
	//	fmt.Printf("droptx: %s", TxToString(tx2))

	return &txid, s.NewOutgoingTx(tx2)
}

// SendOne is for the sweep function, and doesn't do change.
// Probably can get rid of this for real txs.
func (s *SPVCon) SendOne(u Utxo, adr btcutil.Address) (*wire.ShaHash, error) {
	var prevScript []byte

	// fixed fee
	fee := int64(5000)

	sendAmt := u.Value - fee
	tx := wire.NewMsgTx() // make new tx
	// add single output
	outAdrScript, err := txscript.PayToAddrScript(adr)
	if err != nil {
		return nil, err
	}
	// make user specified txout and add to tx
	txout := wire.NewTxOut(sendAmt, outAdrScript)
	tx.AddTxOut(txout)
	tx.AddTxIn(wire.NewTxIn(&u.Op, nil, nil))

	var sig []byte
	var wit [][]byte
	priv := new(btcec.PrivateKey)

	// check if channel close PKH
	if u.FromPeer == 0 {
		priv = s.TS.GetWalletPrivkey(u.KeyIdx)
	} else {
		priv = s.TS.GetRefundPrivkey(u.FromPeer, u.KeyIdx)
	}
	if priv == nil {
		return nil, fmt.Errorf("SendOne: nil privkey")
	}
	hCache := txscript.NewTxSigHashes(tx)
	if u.SpendLag > 1 { // time-delay p2wsh
		if u.AtHeight < 100 {
			return nil, fmt.Errorf("Can't spend %s, timelocked and unconfirmed",
				u.Op.String())
		}
		curHeight, err := s.TS.GetDBSyncHeight()
		if err != nil {
			return nil, err
		}
		if u.AtHeight+u.SpendLag > curHeight {
			return nil, fmt.Errorf(
				"Can't spend %s; spenable at height %d (%d + %d delay) but now %d",
				u.Op.String(),
				u.AtHeight+u.SpendLag, u.AtHeight, u.SpendLag, curHeight)
		}
		// got here; possible to spend.  But need the previous script
		// first get the channel data
		qc, err := s.TS.GetQchanByIdx(u.FromPeer, u.KeyIdx)
		if err != nil {
			return nil, err
		}
		// I need their HAKD pubkey.  I haven't given them the revocation
		// elkrem hash so they haven't been able to spend, and the delay is over.
		// (this assumes the state matches the tx being spent.  It won't
		// work if you're spending from an invalid close that you made.)
		theirHAKDpub, err := qc.MakeTheirHAKDPubkey()
		if err != nil {
			return nil, err
		}
		// need the previous script. ignore builder error
		prevScript, _ = CommitScript2(
			theirHAKDpub, qc.MyRefundPub, uint16(u.SpendLag))
		scriptHash := P2WSHify(prevScript) // p2wsh-ify to check
		fmt.Printf("prevscript: %x\np2wsh'd: %x\n", prevScript, scriptHash)
		// set the sequence field so the OP_CSV works
		tx.TxIn[0].Sequence = uint32(u.SpendLag)
		// make new hash cache for this tx with sequence
		hCache = txscript.NewTxSigHashes(tx)
		// sign with channel refund key and prevScript
		tsig, err := txscript.RawTxInWitnessSignature(
			tx, hCache, 0, u.Value, prevScript, txscript.SigHashAll, priv)
		if err != nil {
			return nil, err
		}

		// witness stack is sig, prevScript
		wit = make([][]byte, 2)
		wit[0] = tsig
		wit[1] = prevScript
		// all set?
	}
	// This is where witness based sighash types need to happen
	// sign into stash
	if u.SpendLag == 0 { // non-witness pkh
		prevAdr, err := btcutil.NewAddressPubKeyHash(
			btcutil.Hash160(priv.PubKey().SerializeCompressed()), s.TS.Param)
		if err != nil {
			return nil, err
		}
		prevScript, err = txscript.PayToAddrScript(prevAdr)
		if err != nil {
			return nil, err
		}
		sig, err = txscript.SignatureScript(
			tx, 0, prevScript, txscript.SigHashAll, priv, true)
		if err != nil {
			return nil, err
		}
	}
	if u.SpendLag == 1 { // witness pkh
		prevAdr, err := btcutil.NewAddressWitnessPubKeyHash(
			btcutil.Hash160(priv.PubKey().SerializeCompressed()), s.TS.Param)
		if err != nil {
			return nil, err
		}
		prevScript, err = txscript.PayToAddrScript(prevAdr)
		if err != nil {
			return nil, err
		}
		wit, err = txscript.WitnessScript(
			tx, hCache, 0, u.Value, prevScript, txscript.SigHashAll, priv, true)
		if err != nil {
			return nil, err
		}
	}

	// swap sigs into sigScripts in txins
	if sig != nil {
		tx.TxIn[0].SignatureScript = sig
	}
	if wit != nil {
		tx.TxIn[0].Witness = wit
		tx.TxIn[0].SignatureScript = nil
	}
	txid := tx.TxSha()
	fmt.Printf("%s", TxToString(tx))
	return &txid, s.NewOutgoingTx(tx)
}

// SendCoins sends coins.
func (s *SPVCon) SendCoins(
	adrs []btcutil.Address, sendAmts []int64) (*wire.ShaHash, error) {

	if len(adrs) != len(sendAmts) {
		return nil, fmt.Errorf(
			"%d addresses and %d amounts", len(adrs), len(sendAmts))
	}
	var err error
	var totalSend int64
	dustCutoff := int64(20000) // below this amount, just give to miners
	satPerByte := int64(80)    // satoshis per byte fee; have as arg later

	for _, amt := range sendAmts {
		totalSend += amt
	}

	tx := wire.NewMsgTx() // make new tx
	// add non-change (arg) outputs
	for i, adr := range adrs {
		// make address script 76a914...88ac or 0014...
		outAdrScript, err := txscript.PayToAddrScript(adr)
		if err != nil {
			return nil, err
		}
		// make user specified txout and add to tx
		txout := wire.NewTxOut(sendAmts[i], outAdrScript)
		tx.AddTxOut(txout)
	}

	changeOut, err := s.TS.NewChangeOut(0)
	if err != nil {
		return nil, err
	}
	tx.AddTxOut(changeOut)
	// get inputs for this tx
	utxos, overshoot, err := s.PickUtxos(totalSend, false)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Overshot by %d, can make change output\n", overshoot)
	// add inputs into tx
	for _, u := range utxos {
		tx.AddTxIn(wire.NewTxIn(&u.Op, nil, nil))
	}

	// estimate fee with outputs, see if change should be truncated
	fee := EstFee(tx, satPerByte)
	changeOut.Value = overshoot - fee
	if changeOut.Value < dustCutoff {
		if changeOut.Value < 0 {
			fmt.Printf("Warning, tx probably has insufficient fee\n")
		}
		// remove last output (change) : not worth it
		tx.TxOut = tx.TxOut[:len(tx.TxOut)-1]
	}

	// sort tx -- this only will change txouts since inputs are already sorted
	txsort.InPlaceSort(tx)

	// tx is ready for signing,
	sigStash := make([][]byte, len(utxos))
	witStash := make([][][]byte, len(utxos))

	// if any of the utxos we're speding have time-locks, the txin sequence
	// has to be set before the hCache is generated.

	// set the txin sequence field so the OP_CSV works. (always in blocks)
	for i, u := range utxos {
		if u.SpendLag > 1 {
			tx.TxIn[i].Sequence = uint32(u.SpendLag)
		}
	}

	// generate tx-wide hashCache for segwit stuff
	hCache := txscript.NewTxSigHashes(tx)

	for i, _ := range tx.TxIn {
		// pick key
		priv := new(btcec.PrivateKey)
		if utxos[i].FromPeer == 0 {
			priv = s.TS.GetWalletPrivkey(utxos[i].KeyIdx)
		} else {
			priv = s.TS.GetRefundPrivkey(utxos[i].FromPeer, utxos[i].KeyIdx)
			// fmt.Printf("sc() made refund pub %x\n", priv.PubKey().SerializeCompressed())
		}
		if priv == nil {
			return nil, fmt.Errorf("SendCoins: nil privkey")
		}

		// sign into stash.  3 possibilities:  PKH, WPKH, timelock WSH
		// HAKD-SH txs are not covered here; those are insta-grabbed for now.
		// (maybe too risky to allow those to be normal txins...)
		if utxos[i].SpendLag == 0 { // non-witness PKH
			prevAdr, err := btcutil.NewAddressPubKeyHash(
				btcutil.Hash160(priv.PubKey().SerializeCompressed()), s.TS.Param)
			if err != nil {
				return nil, err
			}
			prevScript, err := txscript.PayToAddrScript(prevAdr)
			if err != nil {
				return nil, err
			}
			sigStash[i], err = txscript.SignatureScript(tx, i,
				prevScript, txscript.SigHashAll, priv, true)
			if err != nil {
				return nil, err
			}
		}
		if utxos[i].SpendLag == 1 { // witness PKH
			prevAdr, err := btcutil.NewAddressWitnessPubKeyHash(
				btcutil.Hash160(priv.PubKey().SerializeCompressed()), s.TS.Param)
			if err != nil {
				return nil, err
			}
			prevScript, err := txscript.PayToAddrScript(prevAdr)
			if err != nil {
				return nil, err
			}
			witStash[i], err = txscript.WitnessScript(tx, hCache, i,
				utxos[i].Value, prevScript, txscript.SigHashAll, priv, true)
			if err != nil {
				return nil, err
			}
		}
		if utxos[i].SpendLag > 1 { // witness, time-locked SH
			// this utxo is returned by PickUtxos() so should be ready to spend
			// first get the channel data
			qc, err := s.TS.GetQchanByIdx(utxos[i].FromPeer, utxos[i].KeyIdx)
			if err != nil {
				return nil, err
			}
			// Need their HAKD pubkey to build script.  States should line up OK.
			theirHAKDpub, err := qc.MakeTheirHAKDPubkey()
			if err != nil {
				return nil, err
			}
			prevScript, _ := CommitScript2(
				theirHAKDpub, qc.MyRefundPub, uint16(utxos[i].SpendLag))
			// sign with channel refund key and prevScript
			tsig, err := txscript.RawTxInWitnessSignature(
				tx, hCache, i, utxos[i].Value, prevScript, txscript.SigHashAll, priv)
			if err != nil {
				return nil, err
			}
			// witness stack is sig, prevScript
			witStash[i] = make([][]byte, 2)
			witStash[i][0] = tsig
			witStash[i][1] = prevScript
			// all set
		}
	}
	// swap sigs into sigScripts in txins
	for i, txin := range tx.TxIn {
		if sigStash[i] != nil {
			txin.SignatureScript = sigStash[i]
		}
		if witStash[i] != nil {
			txin.Witness = witStash[i]
			txin.SignatureScript = nil
		}

	}

	fmt.Printf("tx: %s", TxToString(tx))
	//	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))

	// send it out on the wire.  hope it gets there.
	// we should deal with rejects.  Don't yet.
	txid := tx.TxSha()
	return &txid, s.NewOutgoingTx(tx)
}

// EstFee gives a fee estimate based on a tx and a sat/Byte target.
// The TX should have all outputs, including the change address already
// populated (with potentially 0 amount.  Also it should have all inputs
// populated, but inputs don't need to have sigscripts or witnesses
// (it'll guess the sizes of sigs/wits that arent' filled in).
func EstFee(otx *wire.MsgTx, spB int64) int64 {
	mtsig := make([]byte, 72)
	mtpub := make([]byte, 33)

	tx := otx.Copy()

	// iterate through txins, replacing subscript sigscripts with noise
	// sigs or witnesses
	for _, txin := range tx.TxIn {
		// check wpkh
		if len(txin.SignatureScript) == 22 &&
			txin.SignatureScript[0] == 0x00 && txin.SignatureScript[1] == 0x14 {
			txin.SignatureScript = nil
			txin.Witness = make([][]byte, 2)
			txin.Witness[0] = mtsig
			txin.Witness[1] = mtpub
		} else if len(txin.SignatureScript) == 34 &&
			txin.SignatureScript[0] == 0x00 && txin.SignatureScript[1] == 0x20 {
			// p2wsh -- sig lenght is a total guess!
			txin.SignatureScript = nil
			txin.Witness = make([][]byte, 3)
			// 3 sigs? totally guessing here
			txin.Witness[0] = mtsig
			txin.Witness[1] = mtsig
			txin.Witness[2] = mtsig
		} else {
			// assume everything else is p2pkh.  Even though it's not
			txin.Witness = nil
			txin.SignatureScript = make([]byte, 105) // len of p2pkh sigscript
		}
	}
	fmt.Printf(TxToString(tx))
	size := int64(blockchain.GetMsgTxVirtualSize(tx))
	tx.SerializeSize()
	fmt.Printf("%d spB, est vsize %d, fee %d\n", spB, size, size*spB)
	return size * spB
}
