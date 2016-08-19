package uspv

import (
	"crypto/rand"
	"fmt"
	"log"
	"sort"

	"github.com/lightningnetwork/lnd/portxo"
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

func (s *SPVCon) GrabAll() error {
	// no args, look through all utxos
	utxos, err := s.TS.GetAllUtxos()
	if err != nil {
		return err
	}

	// currently grabs only confirmed txs.
	nothin := true
	for _, u := range utxos {
		if u.Seq == 1 && u.Height > 0 { // grabbable
			tx, err := s.TS.GrabUtxo(u)
			if err != nil {
				return err
			}
			err = s.NewOutgoingTx(tx)
			if err != nil {
				return err
			}
			nothin = false
		}
	}
	if nothin {
		fmt.Printf("Nothing to grab\n")
	}
	return nil
}

// NewOutgoingTx runs a tx though the db first, then sends it out to the network.
func (s *SPVCon) NewOutgoingTx(tx *wire.MsgTx) error {
	txid := tx.TxSha()
	// assign height of zero for txs we create
	err := s.AddTxid(&txid, 0)
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
func (ts *TxStore) PickUtxos(
	amtWanted int64, ow bool) (portxo.TxoSliceByBip69, int64, error) {
	satPerByte := int64(80) // satoshis per byte fee; have as arg later
	curHeight, err := ts.GetDBSyncHeight()
	if err != nil {
		return nil, 0, err
	}

	var allUtxos portxo.TxoSliceByAmt
	allUtxos, err = ts.GetAllUtxos()
	if err != nil {
		return nil, 0, err
	}

	// start with utxos sorted by value.
	// smallest and unconfirmed last (because it's reversed)
	sort.Sort(sort.Reverse(allUtxos))

	var rSlice portxo.TxoSliceByBip69
	// add utxos until we've had enough
	nokori := amtWanted // nokori is how much is needed on input side
	for _, utxo := range allUtxos {
		// skip unconfirmed.  Or de-prioritize? Some option for this...
		//		if utxo.AtHeight == 0 {
		//			continue
		//		}
		if utxo.Seq > 1 &&
			(utxo.Height < 100 || utxo.Height+int32(utxo.Seq) > curHeight) {
			continue // skip immature or unconfirmed time-locked sh outputs
		}
		if ow && utxo.Seq == 0 {
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
				if txo.Mode&portxo.FlagTxoWitness != 0 {
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

func (t *TxStore) GrabTx(qc *Qchan, idx uint64) (*wire.MsgTx, error) {
	if qc == nil {
		return nil, fmt.Errorf("nil channel")
	}

	return nil, nil
}

// SendDrop sends 2 chained transactions; one to a 2drop script, and then
// one spending that to an address.
// Note that this is completely insecure for any purpose, and
// all it does is waste space.  Kindof useless.
// Returns the 2nd, large tx's txid.
// Probably doesn't work with time-locked.  Doesn't really matter.
func (ts *TxStore) SendDrop(
	u portxo.PorTxo, adr btcutil.Address) (*wire.MsgTx, *wire.MsgTx, error) {
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
	if u.Mode&portxo.FlagTxoWitness != 0 {
		wa, err := btcutil.NewAddressWitnessPubKeyHash(
			ts.Adrs[u.KeyGen.Step[4]].PkhAdr.ScriptAddress(), ts.Param)
		prevPKs, err = txscript.PayToAddrScript(wa)
		if err != nil {
			return nil, nil, err
		}
	} else { // otherwise generate directly
		prevPKs, err = txscript.PayToAddrScript(
			ts.Adrs[u.KeyGen.Step[4]].PkhAdr)
		if err != nil {
			return nil, nil, err
		}
	}
	tx.AddTxIn(wire.NewTxIn(&u.Op, prevPKs, nil))

	var sig []byte
	var wit [][]byte
	hCache := txscript.NewTxSigHashes(tx)

	priv := ts.PathPrivkey(u.KeyGen)
	if priv == nil {
		return nil, nil, fmt.Errorf("SendDrop: nil privkey")
	}

	// This is where witness based sighash types need to happen
	// sign into stash
	if u.Mode&portxo.FlagTxoWitness != 0 {
		wit, err = txscript.WitnessScript(
			tx, hCache, 0, u.Value, tx.TxIn[0].SignatureScript,
			txscript.SigHashAll, priv, true)
		if err != nil {
			return nil, nil, err
		}
	} else {
		sig, err = txscript.SignatureScript(
			tx, 0, tx.TxIn[0].SignatureScript,
			txscript.SigHashAll, priv, true)
		if err != nil {
			return nil, nil, err
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

	tx1id := tx.TxSha()
	sendAmt2 := sendAmt - fee
	tx2 := wire.NewMsgTx() // make new tx

	// now build a NEW tx spending that one!
	// add single output
	outAdrScript, err := txscript.PayToAddrScript(adr)
	if err != nil {
		return nil, nil, err
	}

	txout2 := wire.NewTxOut(sendAmt2, outAdrScript)
	tx2.AddTxOut(txout2)

	dropIn := wire.NewTxIn(wire.NewOutPoint(&tx1id, 0), nil, nil)
	dropIn.Witness = make([][]byte, 17)

	for i, _ := range dropIn.Witness {
		dropIn.Witness[i] = make([]byte, 512)
		_, err := rand.Read(dropIn.Witness[i])
		if err != nil {
			return nil, nil, err
		}
	}
	dropIn.Witness[16] = outpre
	tx2.AddTxIn(dropIn)

	return tx, tx2, nil
}

// SendOne is for the sweep function, and doesn't do change.
// Probably can get rid of this for real txs.
func (ts *TxStore) SendOne(u portxo.PorTxo, adr btcutil.Address) (*wire.MsgTx, error) {
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

	// pick key
	//	if u.KeyGen.Step[3]&0x7fffffff == 0 {
	priv = ts.PathPrivkey(u.KeyGen)
	// shouldn't need this anymore as elkrem is baked in
	/*} else {
		// non-zero peer, channel PKH refund; get channel info to add elkrem
		qc, err := ts.GetQchanByIdx(u.PeerIdx, u.KeyIdx)
		if err != nil {
			return nil, err
		}
		// get the current state sender elkrem hash
		elk, err := qc.ElkSnd.AtIndex(qc.State.StateIdx)
		if err != nil {
			return nil, err
		}
		// not really R, but can't leave as the raw elk hash
		elkHashR := wire.DoubleSha256SH(append(elk.Bytes(), 0x72)) // 'r'

		// generate refund private key from indexes
		priv = ts.GetRefundPrivkey(u.PeerIdx, u.KeyIdx)
		// add elkrem sender hash for the state index
		PrivKeyAddBytes(priv, elkHashR.Bytes())
	}*/

	if priv == nil {
		return nil, fmt.Errorf("SendCoins: nil privkey")
	}
	hCache := txscript.NewTxSigHashes(tx)
	if u.Seq > 1 { // time-delay p2wsh
		if u.Height < 100 {
			return nil, fmt.Errorf("Can't spend %s, timelocked and unconfirmed",
				u.Op.String())
		}
		curHeight, err := ts.GetDBSyncHeight()
		if err != nil {
			return nil, err
		}
		if u.Height+int32(u.Seq) > curHeight {
			return nil, fmt.Errorf(
				"Can't spend %s; spenable at height %d (%d + %d delay) but now %d",
				u.Op.String(),
				u.Height+int32(u.Seq), u.Height, u.Seq, curHeight)
		}
		// got here; possible to spend.  But need the previous script
		// first get the channel data

		priv = ts.PathPrivkey(u.KeyGen)
		// I think that's it and we don't need this stuff

		// I need the pubkeys.  I haven't given them the revocation
		// elkrem hash so they haven't been able to spend, and the delay is over.
		// (this assumes the state matches the tx being spent.  It won't
		// work if you're spending from an invalid close that you made.)
		/*
			qc, err := ts.GetQchanByIdx(u.KeyGen.Step[3], u.KeyGen.Step[4])
			if err != nil {
				return nil, err
			}
			// get the current state elkrem point R (their revocable point)
			elkPointR, err := qc.ElkPoint(false, false, qc.State.StateIdx)
			if err != nil {
				return nil, err
			}

			// get my elkrem T-hash to add to my HAKD base for the timeout key
			elkHash, err := qc.ElkSnd.AtIndex(qc.State.StateIdx)
			if err != nil {
				return nil, err
			}
			elkHashT := wire.DoubleSha256SH(append(elkHash.Bytes(), 0x74)) // 't'

			// get my HAKD base scalar; overwrite priv
			// priv changes here (add their T hash)
			// dont need anymore
			// PrivKeyAddBytes(priv, elkHashT.Bytes())
			// make sure priv is non-nil.  may be redundant
			if priv == nil {
				return nil, fmt.Errorf("nil privkey on timeout spend %s", u.Op.String())
			}

			// make pubkeys for the script
			theirHAKDpub := qc.TheirHAKDBase
			// Construct the revokable pubkey by adding elkrem point R to their HAKD base
			theirHAKDpub = AddPubs(theirHAKDpub, elkPointR)

			var myTimeoutPub [33]byte
			copy(myTimeoutPub[:], priv.PubKey().SerializeCompressed())

			// need the previous script. ignore builder error
			prevScript, _ = CommitScript2(
				theirHAKDpub, myTimeoutPub, uint16(u.Seq))

			scriptHash := P2WSHify(prevScript) // p2wsh-ify to check
			fmt.Printf("prevscript: %x\np2wsh'd: %x\n", prevScript, scriptHash)
		*/
		// set the sequence field so the OP_CSV works
		tx.TxIn[0].Sequence = u.Seq
		// make new hash cache for this tx with sequence
		hCache = txscript.NewTxSigHashes(tx)
		// sign with channel refund key and prevScript
		tsig, err := txscript.RawTxInWitnessSignature(
			tx, hCache, 0, u.Value, u.PkScript, txscript.SigHashAll, priv)
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
	if u.Mode == portxo.TxoP2PKHComp { // non-witness pkh
		prevAdr, err := btcutil.NewAddressPubKeyHash(
			btcutil.Hash160(priv.PubKey().SerializeCompressed()), ts.Param)
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
	if u.Mode == portxo.TxoP2WPKHComp { // witness pkh
		prevAdr, err := btcutil.NewAddressWitnessPubKeyHash(
			btcutil.Hash160(priv.PubKey().SerializeCompressed()), ts.Param)
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
	fmt.Printf("%s", TxToString(tx))
	return tx, nil
}

// SendCoins sends coins.
func (ts *TxStore) SendCoins(
	adrs []btcutil.Address, sendAmts []int64) (*wire.MsgTx, error) {

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

	changeOut, err := ts.NewChangeOut(0)
	if err != nil {
		return nil, err
	}
	tx.AddTxOut(changeOut)
	// get inputs for this tx
	utxos, overshoot, err := ts.PickUtxos(totalSend, false)
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
		if u.Seq > 1 {
			tx.TxIn[i].Sequence = u.Seq
		}
	}

	// generate tx-wide hashCache for segwit stuff
	hCache := txscript.NewTxSigHashes(tx)

	for i, _ := range tx.TxIn {
		// get key
		priv := ts.PathPrivkey(utxos[i].KeyGen)

		/*		if utxos[i].PeerIdx == 0 {
					priv = ts.GetWalletPrivkey(utxos[i].KeyIdx)
				} else {
					// non-zero peer, channel PKH refund; get channel info to add elkrem
					qc, err := ts.GetQchanByIdx(utxos[i].PeerIdx, utxos[i].KeyIdx)
					if err != nil {
						return nil, err
					}
					// get the current state sender elkrem hash
					elk, err := qc.ElkSnd.AtIndex(qc.State.StateIdx)
					if err != nil {
						return nil, err
					}
					// generate refund private key from indexes
					priv = ts.GetRefundPrivkey(utxos[i].PeerIdx, utxos[i].KeyIdx)
					// add elkrem sender hash for the state index
					PrivKeyAddBytes(priv, elk.Bytes())
				}
		*/
		if priv == nil {
			return nil, fmt.Errorf("SendCoins: nil privkey")
		}

		// sign into stash.  4 possibilities:  PKH, WPKH, elk-WPKH, timelock WSH
		// HAKD-SH txs are not covered here; those are insta-grabbed for now.
		// (maybe too risky to allow those to be normal txins...)
		if utxos[i].Mode == portxo.TxoP2PKHComp { // legacy PKH
			sigStash[i], err = txscript.SignatureScript(tx, i,
				utxos[i].PkScript, txscript.SigHashAll, priv, true)
			if err != nil {
				return nil, err
			}
		}
		if utxos[i].Mode&portxo.FlagTxoWitness != 0 { // witnessy
			//			prevAdr, err := btcutil.NewAddressWitnessPubKeyHash(
			//				btcutil.Hash160(priv.PubKey().SerializeCompressed()), ts.Param)
			//			if err != nil {
			//				return nil, err
			//			}
			//			prevScript, err := txscript.PayToAddrScript(prevAdr)
			//			if err != nil {
			//				return nil, err
			//			}
			witStash[i], err = txscript.WitnessScript(tx, hCache, i,
				utxos[i].Value, utxos[i].PkScript, txscript.SigHashAll, priv, true)
			if err != nil {
				return nil, err
			}
		}

		/* ==== can get rid of all this.  I think.
		if utxos[i].Mode == portxo.TxoP2WSHComp { // witness, time-locked SH
			// this utxo is returned by PickUtxos() so should be ready to spend
			// first get the channel data
			qc, err := ts.GetQchanByIdx(utxos[i].PeerIdx, utxos[i].KeyIdx)
			if err != nil {
				return nil, err
			}

			// I need the pubkeys.  I haven't given them the revocation
			// elkrem hash so they haven't been able to spend, and the delay is over.
			// (this assumes the state matches the tx being spent.  It won't
			// work if you're spending from an invalid close that you made.)

			// get the current state elkrem point R (their revocable point)
			elkPointR, err := qc.ElkPoint(false, false, qc.State.StateIdx)
			if err != nil {
				return nil, err
			}

			// get my elkrem T-hash to add to my HAKD base for the timeout key
			elkHash, err := qc.ElkSnd.AtIndex(qc.State.StateIdx)
			if err != nil {
				return nil, err
			}
			elkHashT := wire.DoubleSha256SH(append(elkHash.Bytes(), 0x74)) // 't'

			// get my HAKD base scalar; overwrite priv
			priv = ts.GetHAKDBasePriv(utxos[i].PeerIdx, utxos[i].KeyIdx)
			// priv changes here (add their T hash)
			PrivKeyAddBytes(priv, elkHashT.Bytes())
			// make sure priv is non-nil.  may be redundant
			if priv == nil {
				return nil, fmt.Errorf("nil privkey on timeout spend %s", utxos[i].Op.String())
			}

			// make pubkeys for the script
			theirHAKDpub := qc.TheirHAKDBase
			// Construct the revokable pubkey by adding elkrem point R to their HAKD base
			theirHAKDpub = AddPubs(theirHAKDpub, elkPointR)

			var myTimeoutPub [33]byte
			copy(myTimeoutPub[:], priv.PubKey().SerializeCompressed())

			// need the previous script. ignore builder error
			prevScript, _ := CommitScript2(
				theirHAKDpub, myTimeoutPub, uint16(utxos[i].SpendLag))

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
		*/
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

	return tx, nil
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
