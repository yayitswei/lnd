package uspv

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"sort"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/bloom"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcutil/txsort"
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

type SortableUtxoSlice []Utxo

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
	var score int64
	satPerByte := int64(80) // satoshis per byte fee; have as arg later
	rawUtxos, err := s.TS.GetAllUtxos()
	if err != nil {
		return nil, 0, err
	}

	var allUtxos SortableUtxoSlice
	// start with utxos sorted by value.

	for _, utxo := range rawUtxos {
		score += utxo.Value
		allUtxos = append(allUtxos, *utxo)
	}
	// smallest and unconfirmed last (because it's reversed)
	sort.Sort(sort.Reverse(allUtxos))

	// important rule in bitcoin: output total > input total is invalid.
	if amtWanted > score {
		return nil, 0, fmt.Errorf("wanted %d but %d available.",
			amtWanted, score)
	}

	var rSlice utxoSlice
	// add utxos until we've had enough
	nokori := amtWanted // nokori is how much is needed on input side
	for _, utxo := range allUtxos {
		// skip unconfirmed.  Or de-prioritize?
		//		if utxo.AtHeight == 0 {
		//			continue
		//		}

		if ow && !utxo.IsWit {
			continue // skip non-witness
		}

		// yeah, lets add this utxo!
		rSlice = append(rSlice, utxo)
		nokori -= utxo.Value
		// if nokori is positive, don't bother checking fee yet.
		if nokori < 0 {
			var byteSize int64
			for _, txo := range rSlice {
				if txo.IsWit {
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
	sort.Sort(rSlice) // send sorted
	return rSlice, -nokori, nil
}

func (s *SPVCon) SendDrop(u Utxo, adr btcutil.Address) error {
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
	builder.AddOp(txscript.OP_1)
	outpre, _ := builder.Script()

	txout := wire.NewTxOut(sendAmt, P2WSHify(outpre))
	tx.AddTxOut(txout)

	// build input
	var prevPKs []byte
	if u.IsWit {
		//		tx.Flags = 0x01
		wa, err := btcutil.NewAddressWitnessPubKeyHash(
			s.TS.Adrs[u.KeyIdx].PkhAdr.ScriptAddress(), s.TS.Param)
		prevPKs, err = txscript.PayToAddrScript(wa)
		if err != nil {
			return err
		}
	} else { // otherwise generate directly
		prevPKs, err = txscript.PayToAddrScript(
			s.TS.Adrs[u.KeyIdx].PkhAdr)
		if err != nil {
			return err
		}
	}
	tx.AddTxIn(wire.NewTxIn(&u.Op, prevPKs, nil))

	var sig []byte
	var wit [][]byte
	hCache := txscript.NewTxSigHashes(tx)

	child, err := s.TS.rootPrivKey.Child(u.KeyIdx + hdkeychain.HardenedKeyStart)

	if err != nil {
		return err
	}
	priv, err := child.ECPrivKey()
	if err != nil {
		return err
	}

	// This is where witness based sighash types need to happen
	// sign into stash
	if u.IsWit {
		wit, err = txscript.WitnessScript(
			tx, hCache, 0, u.Value, tx.TxIn[0].SignatureScript,
			txscript.SigHashAll, priv, true)
		if err != nil {
			return err
		}
	} else {
		sig, err = txscript.SignatureScript(
			tx, 0, tx.TxIn[0].SignatureScript,
			txscript.SigHashAll, priv, true)
		if err != nil {
			return err
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
		return err
	}
	tx1id := tx.TxSha()
	sendAmt2 := sendAmt - fee
	tx2 := wire.NewMsgTx() // make new tx

	// now build a NEW tx spending that one!
	// add single output
	outAdrScript, err := txscript.PayToAddrScript(adr)
	if err != nil {
		return err
	}

	txout2 := wire.NewTxOut(sendAmt2, outAdrScript)
	tx2.AddTxOut(txout2)

	dropIn := wire.NewTxIn(wire.NewOutPoint(&tx1id, 0), nil, nil)
	dropIn.Witness = make([][]byte, 11)

	for i, _ := range dropIn.Witness {
		dropIn.Witness[i] = make([]byte, 256)
		_, err := rand.Read(dropIn.Witness[i])
		if err != nil {
			return err
		}
	}
	dropIn.Witness[10] = outpre
	tx2.AddTxIn(dropIn)
	fmt.Printf("droptx: %s", TxToString(tx2))

	return s.NewOutgoingTx(tx2)
}

func (s *SPVCon) SendOne(u Utxo, adr btcutil.Address) error {
	// fixed fee
	fee := int64(5000)

	sendAmt := u.Value - fee
	tx := wire.NewMsgTx() // make new tx
	// add single output
	outAdrScript, err := txscript.PayToAddrScript(adr)
	if err != nil {
		return err
	}
	// make user specified txout and add to tx
	txout := wire.NewTxOut(sendAmt, outAdrScript)
	tx.AddTxOut(txout)

	var prevPKs []byte
	if u.IsWit {
		//		tx.Flags = 0x01
		wa, err := btcutil.NewAddressWitnessPubKeyHash(
			s.TS.Adrs[u.KeyIdx].PkhAdr.ScriptAddress(), s.TS.Param)
		prevPKs, err = txscript.PayToAddrScript(wa)
		if err != nil {
			return err
		}
	} else { // otherwise generate directly
		prevPKs, err = txscript.PayToAddrScript(
			s.TS.Adrs[u.KeyIdx].PkhAdr)
		if err != nil {
			return err
		}
	}

	tx.AddTxIn(wire.NewTxIn(&u.Op, prevPKs, nil))

	var sig []byte
	var wit [][]byte
	hCache := txscript.NewTxSigHashes(tx)

	child, err := s.TS.rootPrivKey.Child(u.KeyIdx + hdkeychain.HardenedKeyStart)

	if err != nil {
		return err
	}
	priv, err := child.ECPrivKey()
	if err != nil {
		return err
	}

	// This is where witness based sighash types need to happen
	// sign into stash
	if u.IsWit {
		wit, err = txscript.WitnessScript(
			tx, hCache, 0, u.Value, tx.TxIn[0].SignatureScript,
			txscript.SigHashAll, priv, true)
		if err != nil {
			return err
		}
	} else {
		sig, err = txscript.SignatureScript(
			tx, 0, tx.TxIn[0].SignatureScript,
			txscript.SigHashAll, priv, true)
		if err != nil {
			return err
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
	return s.NewOutgoingTx(tx)
}

// SendCoins does send coins, but it's very rudimentary
// wit makes it into p2wpkh.  Which is not yet spendable.
func (s *SPVCon) SendCoins(adrs []btcutil.Address, sendAmts []int64) error {
	if len(adrs) != len(sendAmts) {
		return fmt.Errorf("%d addresses and %d amounts", len(adrs), len(sendAmts))
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
			return err
		}
		// make user specified txout and add to tx
		txout := wire.NewTxOut(sendAmts[i], outAdrScript)
		tx.AddTxOut(txout)
	}

	changeOut, err := s.TS.NewChangeOut(0)
	if err != nil {
		return err
	}
	tx.AddTxOut(changeOut)

	// get inputs for this tx
	utxos, overshoot, err := s.PickUtxos(totalSend, false)
	if err != nil {
		return err
	}
	fmt.Printf("Overshot by %d, can make change output\n", overshoot)
	// add inputs into tx
	for _, utxo := range utxos {
		var prevPKScript []byte
		if utxo.IsWit {
			//			tx.Flags = 0x01
			wa, err := btcutil.NewAddressWitnessPubKeyHash(
				s.TS.Adrs[utxo.KeyIdx].PkhAdr.ScriptAddress(), s.TS.Param)
			prevPKScript, err = txscript.PayToAddrScript(wa)
			if err != nil {
				return err
			}
		} else { // otherwise generate directly
			prevPKScript, err = txscript.PayToAddrScript(
				s.TS.Adrs[utxo.KeyIdx].PkhAdr)
			if err != nil {
				return err
			}
		}
		tx.AddTxIn(wire.NewTxIn(&utxo.Op, prevPKScript, nil))
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

	// generate tx-wide hashCache for segwit stuff
	hCache := txscript.NewTxSigHashes(tx)

	for i, txin := range tx.TxIn {
		// pick key
		child, err := s.TS.rootPrivKey.Child(
			utxos[i].KeyIdx + hdkeychain.HardenedKeyStart)
		if err != nil {
			return err
		}
		priv, err := child.ECPrivKey()
		if err != nil {
			return err
		}

		// This is where witness based sighash types need to happen
		// sign into stash
		if utxos[i].IsWit {
			witStash[i], err = txscript.WitnessScript(
				tx, hCache, i, utxos[i].Value, txin.SignatureScript,
				txscript.SigHashAll, priv, true)
			if err != nil {
				return err
			}
		} else {
			sigStash[i], err = txscript.SignatureScript(
				tx, i, txin.SignatureScript,
				txscript.SigHashAll, priv, true)
			if err != nil {
				return err
			}
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
	err = s.NewOutgoingTx(tx)
	if err != nil {
		return err
	}
	return nil
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
	size := int64(tx.VirtualSize())
	tx.SerializeSizeWitness()
	fmt.Printf("%d spB, est vsize %d, fee %d\n", spB, size, size*spB)
	return size * spB
}

// SignThis isn't used anymore...
func (t *TxStore) SignThis(tx *wire.MsgTx) error {
	fmt.Printf("-= SignThis =-\n")

	// sort tx before signing.
	txsort.InPlaceSort(tx)

	sigs := make([][]byte, len(tx.TxIn))
	// first iterate over each input
	for j, in := range tx.TxIn {
		for k := uint32(0); k < uint32(len(t.Adrs)); k++ {
			child, err := t.rootPrivKey.Child(k + hdkeychain.HardenedKeyStart)
			if err != nil {
				return err
			}
			myadr, err := child.Address(t.Param)
			if err != nil {
				return err
			}
			adrScript, err := txscript.PayToAddrScript(myadr)
			if err != nil {
				return err
			}
			if bytes.Equal(adrScript, in.SignatureScript) {
				fmt.Printf("Hit; key %d matches input %d. Signing.\n", k, j)
				priv, err := child.ECPrivKey()
				if err != nil {
					return err
				}
				sigs[j], err = txscript.SignatureScript(
					tx, j, in.SignatureScript, txscript.SigHashAll, priv, true)
				if err != nil {
					return err
				}
				break
			}
		}
	}
	for i, s := range sigs {
		if s != nil {
			tx.TxIn[i].SignatureScript = s
		}
	}
	return nil
}
