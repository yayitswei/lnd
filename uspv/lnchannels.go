package uspv

import (
	"bytes"
	"fmt"

	"github.com/lightningnetwork/lnd/elkrem"
	"github.com/lightningnetwork/lnd/portxo"
	"github.com/lightningnetwork/lnd/sig64"

	"github.com/btcsuite/fastsha256"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/btcutil/txsort"
)

const (
	// high 3 bytes are in sequence, low 3 bytes are in time
	seqMask  = 0xff000000 // assert high byte
	timeMask = 0x21000000 // 1987 to 1988

	MSGID_POINTREQ  = 0x30
	MSGID_POINTRESP = 0x31
	MSGID_CHANDESC  = 0x32
	MSGID_CHANACK   = 0x33
	MSGID_SIGPROOF  = 0x34

	MSGID_CLOSEREQ  = 0x40
	MSGID_CLOSERESP = 0x41

	MSGID_TEXTCHAT = 0x70

	MSGID_RTS    = 0x80 // pushing funds in channel; request to send
	MSGID_ACKSIG = 0x81 // pulling funds in channel; acknowledge update and sign
	MSGID_SIGREV = 0x82 // pushing funds; signing new state and revoking old
	MSGID_REVOKE = 0x83 // pulling funds; revoking previous channel state

	MSGID_FWDMSG     = 0x20
	MSGID_FWDAUTHREQ = 0x21
)

// Uhh, quick channel.  For now.  Once you get greater spire it upgrades to
// a full channel that can do everything.
type Qchan struct {
	// S for stored (on disk), D for derived

	portxo.PorTxo            // S underlying utxo data
	CloseData     QCloseData // S closing outpoint

	MyPub    [33]byte // D my channel specific pubkey
	TheirPub [33]byte // S their channel specific pubkey

	PeerId [33]byte // D useful for quick traverse of db

	// Refunds are also elkremified
	MyRefundPub    [33]byte // D my refund pubkey for channel break
	TheirRefundPub [33]byte // S their pubkey for channel break

	MyHAKDBase    [33]byte // D my base point for HAKD and timeout keys
	TheirHAKDBase [33]byte // S their base point for HAKD and timeout keys

	// Elkrem is used for revoking state commitments
	ElkSnd *elkrem.ElkremSender   // D derived from channel specific key
	ElkRcv *elkrem.ElkremReceiver // S stored in db

	TimeOut uint16 // blocks for timeout (default 5 for testing)

	State *StatCom // S state of channel
}

// StatComs are State Commitments.
// all elements are saved to the db.
type StatCom struct {
	StateIdx uint64 // this is the n'th state commitment

	MyAmt int64 // my channel allocation
	// their Amt is the utxo.Value minus this
	Delta int32 // fun amount in-transit; is negative for the pusher

	// Elkrem point from counterparty, used to make
	// Homomorphic Adversarial Key Derivation public keys (HAKD)
	ElkPointR     [33]byte // saved to disk, revealable point
	PrevElkPointR [33]byte // When you haven't gotten their revocation elkrem yet.

	ElkPointT     [33]byte // their timeout elk point; needed for script
	PrevElkPointT [33]byte // When you haven't gotten their revocation elkrem yet.

	sig [64]byte // Counterparty's signature (for StatCom tx)
	// don't write to sig directly; only overwrite via fn() call

	// note sig can be nil during channel creation. if stateIdx isn't 0,
	// sig should have a sig.
	// only one sig is ever stored, to prevent broadcasting the wrong tx.
	// could add a mutex here... maybe will later.
}

// QCloseData is the output resulting from an un-cooperative close
// of the channel.  This happens when either party breaks non-cooperatively.
// It describes "your" output, either pkh or time-delay script.
// If you have pkh but can grab the other output, "grabbable" is set to true.
// This can be serialized in a separate bucket

type QCloseData struct {
	// 3 txid / height pairs are stored.  All 3 only are used in the
	// case where you grab their invalid close.
	CloseTxid   wire.ShaHash
	CloseHeight int32
	Closed      bool // if channel is closed; if CloseTxid != -1
}

// GetStateIdxFromTx returns the state index from a commitment transaction.
// No errors; returns 0 if there is no retrievable index.
// Takes the xor input X which is derived from the 0th elkrems.
func GetStateIdxFromTx(tx *wire.MsgTx, x uint64) uint64 {
	// no tx, so no index
	if tx == nil {
		return 0
	}
	// more than 1 input, so not a close tx
	if len(tx.TxIn) != 1 {
		return 0
	}
	if x >= 1<<48 {
		return 0
	}
	// check that indicating high bytes are correct
	if tx.TxIn[0].Sequence>>24 != 0xff || tx.LockTime>>24 != 0x21 {
		//		fmt.Printf("sequence byte %x, locktime byte %x\n",
		//			tx.TxIn[0].Sequence>>24, tx.LockTime>>24 != 0x21)
		return 0
	}
	// high 24 bits sequence, low 24 bits locktime
	seqBits := uint64(tx.TxIn[0].Sequence & 0x00ffffff)
	timeBits := uint64(tx.LockTime & 0x00ffffff)

	return (seqBits<<24 | timeBits) ^ x
}

// SetStateIdxBits modifies the tx in place, setting the sequence and locktime
// fields to indicate the given state index.
func SetStateIdxBits(tx *wire.MsgTx, idx, x uint64) error {
	if tx == nil {
		return fmt.Errorf("SetStateIdxBits: nil tx")
	}
	if len(tx.TxIn) != 1 {
		return fmt.Errorf("SetStateIdxBits: tx has %d inputs", len(tx.TxIn))
	}
	if idx >= 1<<48 {
		return fmt.Errorf(
			"SetStateIdxBits: index %d greater than max %d", idx, uint64(1<<48)-1)
	}

	idx = idx ^ x
	// high 24 bits sequence, low 24 bits locktime
	seqBits := uint32(idx >> 24)
	timeBits := uint32(idx & 0x00ffffff)

	tx.TxIn[0].Sequence = seqBits | seqMask
	tx.LockTime = timeBits | timeMask

	return nil
}

// GetCloseTxos takes in a tx and sets the QcloseTXO feilds based on the tx.
// It also returns the spendable (u)txos generated by the close.
func (q *Qchan) GetCloseTxos(tx *wire.MsgTx) ([]portxo.PorTxo, error) {
	if tx == nil {
		return nil, fmt.Errorf("IngesGetCloseTxostCloseTx: nil tx")
	}
	txid := tx.TxSha()
	// double check -- does this tx actually close the channel?
	if !(len(tx.TxIn) == 1 && OutPointsEqual(tx.TxIn[0].PreviousOutPoint, q.Op)) {
		return nil, fmt.Errorf("tx %s doesn't spend channel outpoint %s",
			txid.String(), q.Op.String())
	}
	// hardcode here now... need to save to qchan struct I guess
	q.TimeOut = 5
	x := q.GetElkZeroOffset()
	if x >= 1<<48 {
		return nil, fmt.Errorf("GetCloseTxos elkrem error, x= %x", x)
	}
	// first, check if cooperative
	txIdx := GetStateIdxFromTx(tx, x)
	if txIdx > q.State.StateIdx { // future state, uhoh.  Crash for now.
		return nil, fmt.Errorf("indicated state %d but we know up to %d",
			txIdx, q.State.StateIdx)
	}

	if txIdx == 0 || len(tx.TxOut) != 2 {
		// must have been cooperative, or something else we don't recognize
		// if simple close, still have a PKH output, find it.
		// so far, assume 1 txo

		// no txindx hint, so it's probably cooperative, so most recent
		theirElkPointR, err := q.ElkPoint(false, false, q.State.StateIdx)
		if err != nil {
			return nil, err
		}

		myRefundArr := AddPubs(theirElkPointR, q.MyRefundPub)
		myPKH := btcutil.Hash160(myRefundArr[:])

		var pkhTxo portxo.PorTxo
		for i, out := range tx.TxOut {
			if len(out.PkScript) < 22 {
				continue // skip to prevent crash
			}
			if bytes.Equal(out.PkScript[2:22], myPKH) { // detected my refund
				// use most recent elk, as cooperative
				elk, err := q.ElkRcv.AtIndex(q.State.StateIdx)
				if err != nil {
					return nil, err
				}
				// hash elkrem into elkrem R scalar (0x72 == 'r')
				pkhTxo.PrivKey = wire.DoubleSha256SH(append(elk.Bytes(), 0x72))

				pkhTxo.Op.Hash = txid
				pkhTxo.Op.Index = uint32(i)
				pkhTxo.Height = q.CloseData.CloseHeight
				// keypath is the same other than use
				pkhTxo.KeyGen = q.KeyGen
				pkhTxo.KeyGen.Step[2] = UseChannelRefund

				pkhTxo.Value = tx.TxOut[i].Value
				pkhTxo.Mode = portxo.TxoP2WPKHComp // witness, non time locked, PKH
				return []portxo.PorTxo{pkhTxo}, nil
			}
		}
		// couldn't find anything... shouldn't happen
		return nil, fmt.Errorf("channel closed but we got nothing!")
	}

	// non-cooperative / break.

	var shIdx, pkhIdx uint32
	cTxos := make([]portxo.PorTxo, 1)
	// sort outputs into PKH and SH
	if len(tx.TxOut[0].PkScript) == 34 {
		shIdx = 0
		pkhIdx = 1
	} else {
		pkhIdx = 0
		shIdx = 1
	}
	// make sure SH output is actually SH
	if len(tx.TxOut[shIdx].PkScript) != 34 {
		return nil, fmt.Errorf("non-p2sh output is length %d, expect 34",
			len(tx.TxOut[shIdx].PkScript))
	}
	// make sure PKH output is actually PKH
	if len(tx.TxOut[pkhIdx].PkScript) != 22 {
		return nil, fmt.Errorf("non-p2wsh output is length %d, expect 22",
			len(tx.TxOut[pkhIdx].PkScript))
	}

	// use the indicated state to generate refund pkh (it may be old)

	// refund PKHs come from the refund base plus their elkrem point R.
	theirElkPointR, err := q.ElkPoint(false, false, txIdx)
	if err != nil {
		return nil, err
	}
	theirElkPointT, err := q.ElkPoint(false, true, txIdx)
	if err != nil {
		return nil, err
	}

	myRefundArr := AddPubs(theirElkPointR, q.MyRefundPub)
	myPKH := btcutil.Hash160(myRefundArr[:])

	// indirectly check if SH is mine
	if !bytes.Equal(tx.TxOut[pkhIdx].PkScript[2:22], myPKH) {
		// ------------pkh not mine; assume SH is mine
		// build script to store in porTxo
		timeoutPub := AddPubs(q.TheirHAKDBase, theirElkPointT)
		revokePub := AddPubs(q.MyHAKDBase, theirElkPointR)

		script, err := CommitScript2(revokePub, timeoutPub, q.TimeOut)
		if err != nil {
			return nil, err
		}

		var shTxo portxo.PorTxo // create new utxo and copy into it
		// use txidx's elkrem as it may not be most recent
		elk, err := q.ElkSnd.AtIndex(txIdx)
		if err != nil {
			return nil, err
		}
		// hash elkrem into elkrem T scalar (0x74 == 't')
		shTxo.PrivKey = wire.DoubleSha256SH(append(elk.Bytes(), 0x74))

		shTxo.Op.Hash = txid
		shTxo.Op.Index = shIdx
		shTxo.Height = q.CloseData.CloseHeight
		// keypath is the same, except for use
		shTxo.KeyGen = q.KeyGen
		shTxo.KeyGen.Step[2] = UseChannelHAKDBase

		shTxo.Mode = portxo.TxoP2WSHComp

		shTxo.Value = tx.TxOut[shIdx].Value
		shTxo.Seq = uint32(q.TimeOut)

		// TODO add script check
		shTxo.PkScript = script

		cTxos[0] = shTxo
		// if SH is mine we're done
		return cTxos, nil
	}

	// ---------- pkh is mine
	var pkhTxo portxo.PorTxo // create new utxo and copy into it

	// use txidx's elkrem as it may not be most recent
	elk, err := q.ElkSnd.AtIndex(txIdx)
	if err != nil {
		return nil, err
	}
	// hash elkrem into elkrem R scalar (0x72 == 'r')
	pkhTxo.PrivKey = wire.DoubleSha256SH(append(elk.Bytes(), 0x72))
	elkPointR := PubFromHash(*elk)
	combined := AddPubs(elkPointR, q.MyRefundPub)
	pkh := btcutil.Hash160(combined[:])
	if !bytes.Equal(tx.TxOut[pkhIdx].PkScript[2:], pkh) {
		fmt.Printf("got different observed and generated pkh scripts.\n")
		fmt.Printf("in %s : %d see %x\n", txid, pkhIdx, tx.TxOut[pkhIdx].PkScript)
		fmt.Printf("generated %x from sender (/ their) elkR %d\n", pkh, txIdx)
		fmt.Printf("base refund pub %x\n", q.MyRefundPub)
	}

	pkhTxo.Op.Hash = txid
	pkhTxo.Op.Index = pkhIdx
	pkhTxo.Height = q.CloseData.CloseHeight
	// keypath same, use different
	pkhTxo.KeyGen = q.KeyGen
	// same keygen as underlying channel, but use is refund
	pkhTxo.KeyGen.Step[2] = UseChannelRefund
	pkhTxo.Mode = portxo.TxoP2WPKHComp
	pkhTxo.Value = tx.TxOut[pkhIdx].Value
	// PKH, so script is easy
	pkhTxo.PkScript = tx.TxOut[pkhIdx].PkScript
	cTxos[0] = pkhTxo

	// OK, it's my PKH, but can I grab the SH???
	if txIdx < q.State.StateIdx {
		// invalid previous state, can be grabbed!
		// make MY elk points
		myElkPointR, err := q.ElkPoint(true, false, txIdx)
		if err != nil {
			return nil, err
		}
		myElkPointT, err := q.ElkPoint(true, true, txIdx)
		if err != nil {
			return nil, err
		}
		timeoutPub := AddPubs(q.TheirHAKDBase, myElkPointT)
		revokePub := AddPubs(q.MyHAKDBase, myElkPointR)
		script, err := CommitScript2(revokePub, timeoutPub, q.TimeOut)
		if err != nil {
			return nil, err
		}

		// myElkHashR added to HAKD private key
		elk, err := q.ElkRcv.AtIndex(txIdx)
		if err != nil {
			return nil, err
		}

		var shTxo portxo.PorTxo // create new utxo and copy into it
		shTxo.Op.Hash = txid
		shTxo.Op.Index = shIdx
		shTxo.Height = q.CloseData.CloseHeight

		shTxo.KeyGen = q.KeyGen
		shTxo.KeyGen.Step[2] = UseChannelHAKDBase

		pkhTxo.PrivKey = wire.DoubleSha256SH(append(elk.Bytes(), 0x72)) // 'r'

		shTxo.PkScript = script

		shTxo.Value = tx.TxOut[shIdx].Value
		shTxo.Seq = 1 // 1 means grab immediately
		cTxos = append(cTxos, shTxo)
	}

	return cTxos, nil
}

// ChannelInfo prints info about a channel.
func (t *TxStore) QchanInfo(q *Qchan) error {
	// display txid instead of outpoint because easier to copy/paste
	fmt.Printf("CHANNEL %s h:%d %s cap: %d\n",
		q.Op.Hash.String(), q.Height, q.KeyGen.String(), q.Value)
	fmt.Printf("\tPUB mine:%x them:%x REFBASE mine:%x them:%x BASE mine:%x them:%x\n",
		q.MyPub[:4], q.TheirPub[:4], q.MyRefundPub[:4], q.TheirRefundPub[:4],
		q.MyHAKDBase[:4], q.TheirHAKDBase[:4])
	if q.State == nil || q.ElkRcv == nil {
		fmt.Printf("\t no valid state or elkrem\n")
	} else {

		fmt.Printf("\ta %d (them %d) state index %d\n",
			q.State.MyAmt, q.Value-q.State.MyAmt, q.State.StateIdx)

		fmt.Printf("\tdelta:%d HAKD:%x prevHAKD:%x elk@ %d\n",
			q.State.Delta, q.State.ElkPointR[:4], q.State.PrevElkPointR[:4],
			q.ElkRcv.UpTo())
		elkp, _ := q.ElkPoint(false, false, q.State.StateIdx)
		myRefPub := AddPubs(q.MyRefundPub, elkp)

		theirRefPub := AddPubs(q.TheirRefundPub, q.State.ElkPointT)
		fmt.Printf("\tMy Refund: %x Their Refund %x\n", myRefPub[:4], theirRefPub[:4])
	}

	if !q.CloseData.Closed { // still open, finish here
		return nil
	}

	fmt.Printf("\tCLOSED at height %d by tx: %s\n",
		q.CloseData.CloseHeight, q.CloseData.CloseTxid.String())
	clTx, err := t.GetTx(&q.CloseData.CloseTxid)
	if err != nil {
		return err
	}
	ctxos, err := q.GetCloseTxos(clTx)
	if err != nil {
		return err
	}

	if len(ctxos) == 0 {
		fmt.Printf("\tcooperative close.\n")
		return nil
	}

	fmt.Printf("\tClose resulted in %d spendable txos\n", len(ctxos))
	if len(ctxos) == 2 {
		fmt.Printf("\t\tINVALID CLOSE!!!11\n")
	}
	for i, u := range ctxos {
		fmt.Printf("\t\t%d) amt: %d spendable: %d\n", i, u.Value, u.Seq)
	}
	return nil
}

// GrabTx produces the "remedy" transaction to get all the money if they
// broadcast an old state which they invalidated.
// This function assumes a recovery is possible; if it can't construct the right
// keys and scripts it will return an error.
func (t *TxStore) GrabUtxo(u *portxo.PorTxo) (*wire.MsgTx, error) {
	if u == nil {
		return nil, fmt.Errorf("GrabUtxo Grab error: nil utxo")
	}
	// this utxo is returned by PickUtxos() so should be ready to spend
	// first get the channel data
	qc, err := t.GetQchanByIdx(u.KeyGen.Step[3], u.KeyGen.Step[4])
	if err != nil {
		return nil, err
	}

	// load closing tx
	closeTx, err := t.GetTx(&qc.CloseData.CloseTxid)
	if err != nil {
		return nil, err
	}
	if len(closeTx.TxOut) != 2 { // (could be more later; onehop is 2)
		return nil, fmt.Errorf("GrabUtxo close tx has %d outputs, can't grab",
			len(closeTx.TxOut))
	}
	if len(closeTx.TxOut[u.Op.Index].PkScript) != 34 {
		return nil, fmt.Errorf("GrabUtxo grab txout pkscript length %d, expect 34",
			len(closeTx.TxOut[u.Op.Index].PkScript))
	}

	x := qc.GetElkZeroOffset()
	if x >= 1<<48 {
		return nil, fmt.Errorf("GrabUtxo elkrem error, x= %x", x)
	}
	// find state index based on tx hints (locktime / sequence)
	txIdx := GetStateIdxFromTx(closeTx, x)
	if txIdx == 0 {
		return nil, fmt.Errorf("GrabUtxo no hint, can't recover")
	}

	//	t.GrabTx(qc, txIdx)
	shOut := closeTx.TxOut[u.Op.Index]
	// if hinted state is greater than elkrem state we can't recover
	if txIdx > qc.ElkRcv.UpTo() {
		return nil, fmt.Errorf("GrabUtxo tx at state %d but elkrem only goes to %d",
			txIdx, qc.ElkRcv.UpTo())
	}

	// get elk T point for their timeout pubkey
	elkT, err := qc.ElkPoint(true, true, txIdx)
	if err != nil {
		return nil, err
	}

	// get raw elkrem hash
	elk, err := qc.ElkRcv.AtIndex(txIdx)
	if err != nil {
		return nil, err
	}
	fmt.Printf("made elk %s at index %d\n", elk.String(), txIdx)
	// hash elkrem into elkrem R scalar
	elkR := wire.DoubleSha256SH(append(elk.Bytes(), 0x72)) // 'r'

	// get HAKD base scalar
	priv := t.GetUsePriv(qc.KeyGen, UseChannelHAKDBase)
	fmt.Printf("made chan pub %x\n", priv.PubKey().SerializeCompressed())
	// add HAKD base scalar and elkrem R scalar for R private key
	PrivKeyAddBytes(priv, elkR.Bytes())

	// serialize pubkey part for script generation
	var HAKDpubArr [33]byte
	copy(HAKDpubArr[:], priv.PubKey().SerializeCompressed())
	fmt.Printf("made HAKD to recover from %x\n", HAKDpubArr)

	// add the elkT point to their base point for timeout pubkey
	theirTimeoutPub := AddPubs(qc.TheirHAKDBase, elkT)

	// now that everything is chosen, build fancy script and pkh script
	preScript, _ := CommitScript2(HAKDpubArr, theirTimeoutPub, qc.TimeOut)
	fancyScript := P2WSHify(preScript) // p2wsh-ify
	fmt.Printf("prescript: %x\np2wshd: %x\n", preScript, fancyScript)
	if !bytes.Equal(fancyScript, shOut.PkScript) {
		return nil, fmt.Errorf("GrabUtxo script hash mismatch, generated %x expect %x",
			fancyScript, shOut.PkScript)
	}

	// build tx and sign.
	sweepTx := wire.NewMsgTx()
	destTxOut, err := t.NewChangeOut(shOut.Value - 5000) // fixed fee for now
	if err != nil {
		return nil, err
	}
	sweepTx.AddTxOut(destTxOut)

	// add unsigned input
	sweepIn := wire.NewTxIn(&u.Op, nil, nil)
	sweepTx.AddTxIn(sweepIn)

	// make hash cache for this tx
	hCache := txscript.NewTxSigHashes(sweepTx)

	// sign
	sig, err := txscript.RawTxInWitnessSignature(
		sweepTx, hCache, 0, shOut.Value, preScript, txscript.SigHashAll, priv)

	sweepTx.TxIn[0].Witness = make([][]byte, 2)
	sweepTx.TxIn[0].Witness[0] = sig
	sweepTx.TxIn[0].Witness[1] = preScript
	// that's it...?

	return sweepTx, nil
}

// GetElkZeroOffset returns a 48-bit uint (cast up to 8 bytes) based on the sender
// and receiver elkrem at index 0.  If there's an error, it returns ff...
func (q *Qchan) GetElkZeroOffset() uint64 {
	theirZero, err := q.ElkRcv.AtIndex(0)
	if err != nil {
		fmt.Printf(err.Error())
		return 0xffffffffffffffff
	}
	myZero, err := q.ElkSnd.AtIndex(0)
	if err != nil {
		fmt.Printf(err.Error())
		return 0xffffffffffffffff
	}
	theirBytes := theirZero.Bytes()
	myBytes := myZero.Bytes()
	x := make([]byte, 8)
	for i := 2; i < 8; i++ {
		x[i] = myBytes[i] ^ theirBytes[i]
	}

	// only 48 bits so will be OK when cast to signed 64 bit
	return uint64(BtI64(x[:]))
}

// MakeTheirCurElkPoint makes the current state elkrem points to send out
func (q *Qchan) MakeTheirCurElkPoints() (r, t [33]byte, err error) {
	// generate revocable elkrem point
	r, err = q.ElkPoint(false, false, q.State.StateIdx)
	if err != nil {
		return
	}
	// generate timeout elkrem point
	t, err = q.ElkPoint(false, true, q.State.StateIdx)
	return
}

// ElkPoint generates an elkrem Point.  "My" elkrem point is the point
// I receive from the counter party, and can create after the state has
// been revoked.  "Their" elkrem point (mine=false) is generated from my elkrem
// sender at any index.
// Elkrem points are sub-hashes of the hash coming from the elkrem tree.
// There are "time" and "revoke" elkrem points, which are just sha2d(elk, "t")
// and sha2d(elk, "r") of the hash from the elkrem tree.
// Having different points prevents observers from distinguishing the channel
// when they have the HAKD base points but not the elkrem point.
func (q *Qchan) ElkPoint(mine, time bool, idx uint64) (p [33]byte, err error) {
	// sanity check
	if q == nil || q.ElkSnd == nil || q.ElkRcv == nil { // can't do anything
		err = fmt.Errorf("can't access elkrem")
		return
	}
	elk := new(wire.ShaHash)

	if mine { // make mine based on receiver
		elk, err = q.ElkRcv.AtIndex(idx)
	} else { // make theirs based on sender
		elk, err = q.ElkSnd.AtIndex(idx)
	}
	// elkrem problem, error out here
	if err != nil {
		return
	}

	if time {
		*elk = wire.DoubleSha256SH(append(elk.Bytes(), 0x74)) // ascii "t"
	} else {
		*elk = wire.DoubleSha256SH(append(elk.Bytes(), 0x72)) // ascii "r"
	}

	// turn the hash into a point
	p = PubFromHash(*elk)
	return
}

// IngestElkrem takes in an elkrem hash, performing 2 checks:
// that it produces the proper elk point, and that it fits into the elkrem tree.
// if both of these are the case it updates the channel state, removing the
// revoked point. If either of these checks fail, and definitely the second one
// fails, I'm pretty sure the channel is not recoverable and needs to be closed.
func (q *Qchan) IngestElkrem(elk *wire.ShaHash) error {
	if elk == nil {
		return fmt.Errorf("IngestElkrem: nil hash")
	}

	// first verify the elkrem insertion (this only performs checks 1/2 the time, so
	// 1/2 the time it'll work even if the elkrem is invalid, oh well)
	err := q.ElkRcv.AddNext(elk)
	if err != nil {
		return err
	}
	fmt.Printf("ingested hash, receiver now has up to %d\n", q.ElkRcv.UpTo())

	// if this is state 1, then we have elkrem 0 and we can stop here.
	// there's nothing to revoke.
	if q.State.StateIdx == 1 {
		return nil
	}

	// next verify if the elkrem produces the previous elk point.
	// We don't actually use the private key operation here, because we can
	// do the same operation on our pubkey that they did, and we have faith
	// in the mysterious power of abelian group homomorphisms that the private
	// key modification will also work.

	// Make r and t points from received elk hash
	CheckR := PubFromHash(wire.DoubleSha256SH(append(elk.Bytes(), 0x72))) // r
	CheckT := PubFromHash(wire.DoubleSha256SH(append(elk.Bytes(), 0x74))) // t

	// see if it matches previous elk point
	if CheckR != q.State.PrevElkPointR || CheckT != q.State.PrevElkPointT {
		// didn't match, the whole channel is borked.
		return fmt.Errorf("hash %x (index %d) fits tree but creates wrong elkpoint!",
			elk[:8], q.State.PrevElkPointR, q.State.PrevElkPointT)
	}

	// it did match, so we can clear the previous HAKD pub
	var empty [33]byte
	q.State.PrevElkPointR = empty
	q.State.PrevElkPointT = empty

	return nil
}

// SignBreak signs YOUR tx, which you already have a sig for
func (t TxStore) SignBreakTx(q *Qchan) (*wire.MsgTx, error) {
	tx, err := q.BuildStateTx(true)
	if err != nil {
		return nil, err
	}

	// make hash cache for this tx
	hCache := txscript.NewTxSigHashes(tx)

	// generate script preimage (keep track of key order)
	pre, swap, err := FundTxScript(q.MyPub, q.TheirPub)
	if err != nil {
		return nil, err
	}

	// get private signing key
	priv := t.PathPrivkey(q.KeyGen)
	// generate sig.
	mySig, err := txscript.RawTxInWitnessSignature(
		tx, hCache, 0, q.Value, pre, txscript.SigHashAll, priv)

	theirSig := sig64.SigDecompress(q.State.sig)
	// put the sighash all byte on the end of their signature
	theirSig = append(theirSig, byte(txscript.SigHashAll))

	fmt.Printf("made mysig: %x theirsig: %x\n", mySig, theirSig)
	// add sigs to the witness stack
	if swap {
		tx.TxIn[0].Witness = SpendMultiSigWitStack(pre, theirSig, mySig)
	} else {
		tx.TxIn[0].Witness = SpendMultiSigWitStack(pre, mySig, theirSig)
	}
	return tx, nil
}

// SimpleCloseTx produces a close tx based on the current state.
// The PKH addresses are my refund base with their r-elkrem point, and
// their refund base with my r-elkrem point.  "Their" point means they have
// the point but not the scalar.
func (q *Qchan) SimpleCloseTx() (*wire.MsgTx, error) {
	// sanity checks
	if q == nil || q.State == nil {
		return nil, fmt.Errorf("SimpleCloseTx: nil chan / state")
	}
	fee := int64(5000) // fixed fee for now (on both sides)

	// get final elkrem points; both R, theirs and mine
	theirElkPointR, err := q.ElkPoint(false, false, q.State.StateIdx)
	if err != nil {
		fmt.Printf("SimpleCloseTx: can't generate elkpoint.")
		return nil, err
	}

	// my pub is my base and "their" elk point which I have the scalar for
	myRefundPub := AddPubs(q.MyRefundPub, theirElkPointR)
	// their pub is their base and "my" elk point (which they gave me)
	theirRefundPub := AddPubs(q.TheirRefundPub, q.State.ElkPointR)

	// make my output
	myScript := DirectWPKHScript(myRefundPub)
	myOutput := wire.NewTxOut(q.State.MyAmt-fee, myScript)
	// make their output
	theirScript := DirectWPKHScript(theirRefundPub)
	theirOutput := wire.NewTxOut((q.Value-q.State.MyAmt)-fee, theirScript)

	// make tx with these outputs
	tx := wire.NewMsgTx()
	tx.AddTxOut(myOutput)
	tx.AddTxOut(theirOutput)
	// add channel outpoint as txin
	tx.AddTxIn(wire.NewTxIn(&q.Op, nil, nil))
	// sort and return
	txsort.InPlaceSort(tx)
	return tx, nil
}

// SignSimpleClose creates a close tx based on the current state and signs it,
// returning that sig.  Also returns a bool; true means this sig goes second.
func (t TxStore) SignSimpleClose(q *Qchan) ([]byte, error) {
	tx, err := q.SimpleCloseTx()
	if err != nil {
		return nil, err
	}
	// make hash cache
	hCache := txscript.NewTxSigHashes(tx)

	// generate script preimage for signing (ignore key order)
	pre, _, err := FundTxScript(q.MyPub, q.TheirPub)
	if err != nil {
		return nil, err
	}
	// get private signing key
	priv := t.GetUsePriv(q.KeyGen, UseChannelFund)
	// generate sig
	sig, err := txscript.RawTxInWitnessSignature(
		tx, hCache, 0, q.Value, pre, txscript.SigHashAll, priv)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// SignNextState generates your signature for their state.
func (t TxStore) SignState(q *Qchan) ([64]byte, error) {
	var sig [64]byte
	// build transaction for next state
	tx, err := q.BuildStateTx(false) // their tx, as I'm signing
	if err != nil {
		return sig, err
	}

	// make hash cache for this tx
	hCache := txscript.NewTxSigHashes(tx)

	// generate script preimage (ignore key order)
	pre, _, err := FundTxScript(q.MyPub, q.TheirPub)
	if err != nil {
		return sig, err
	}

	// get private signing key
	priv := t.PathPrivkey(q.KeyGen)

	// generate sig.
	bigSig, err := txscript.RawTxInWitnessSignature(
		tx, hCache, 0, q.Value, pre, txscript.SigHashAll, priv)
	// truncate sig (last byte is sighash type, always sighashAll)
	bigSig = bigSig[:len(bigSig)-1]

	sig, err = sig64.SigCompress(bigSig)
	if err != nil {
		return sig, err
	}

	fmt.Printf("____ sig creation for channel (%d,%d):\n", q.KeyGen.Step[3], q.KeyGen.Step[4])
	fmt.Printf("\tinput %s\n", tx.TxIn[0].PreviousOutPoint.String())
	fmt.Printf("\toutput 0: %x %d\n", tx.TxOut[0].PkScript, tx.TxOut[0].Value)
	fmt.Printf("\toutput 1: %x %d\n", tx.TxOut[1].PkScript, tx.TxOut[1].Value)
	fmt.Printf("\tstate %d myamt: %d theiramt: %d\n", q.State.StateIdx, q.State.MyAmt, q.Value-q.State.MyAmt)

	return sig, nil
}

// VerifySig verifies their signature for your next state.
// it also saves the sig if it's good.
// do bool, error or just error?  Bad sig is an error I guess.
// for verifying signature, always use theirHAKDpub, so generate & populate within
// this function.
func (q *Qchan) VerifySig(sig [64]byte) error {

	bigSig := sig64.SigDecompress(sig)
	// my tx when I'm verifying.
	tx, err := q.BuildStateTx(true)
	if err != nil {
		return err
	}

	// generate fund output script preimage (ignore key order)
	pre, _, err := FundTxScript(q.MyPub, q.TheirPub)
	if err != nil {
		return err
	}

	hCache := txscript.NewTxSigHashes(tx)
	// always sighash all
	hash, err := txscript.CalcWitnessSigHash(
		pre, hCache, txscript.SigHashAll, tx, 0, q.Value)
	if err != nil {
		return err
	}

	// sig is pre-truncated; last byte for sighashtype is always sighashAll
	pSig, err := btcec.ParseDERSignature(bigSig, btcec.S256())
	if err != nil {
		return err
	}
	theirPubKey, err := btcec.ParsePubKey(q.TheirPub[:], btcec.S256())
	if err != nil {
		return err
	}
	fmt.Printf("____ sig verification for channel (%d,%d):\n", q.KeyGen.Step[3], q.KeyGen.Step[4])
	fmt.Printf("\tinput %s\n", tx.TxIn[0].PreviousOutPoint.String())
	fmt.Printf("\toutput 0: %x %d\n", tx.TxOut[0].PkScript, tx.TxOut[0].Value)
	fmt.Printf("\toutput 1: %x %d\n", tx.TxOut[1].PkScript, tx.TxOut[1].Value)
	fmt.Printf("\tstate %d myamt: %d theiramt: %d\n", q.State.StateIdx, q.State.MyAmt, q.Value-q.State.MyAmt)
	fmt.Printf("\tsig: %x\n", sig)

	worked := pSig.Verify(hash, theirPubKey)
	if !worked {
		return fmt.Errorf("Their sig was no good!!!!!111")
	}

	// copy signature, overwriting old signature.
	q.State.sig = sig

	return nil
}

// BuildStateTx constructs and returns a state tx.  As simple as I can make it.
// This func just makes the tx with data from State in ram, and HAKD key arg
// Delta should always be 0 when making this tx.
// It decides whether to make THEIR tx or YOUR tx based on the HAKD pubkey given --
// if it's zero, then it makes their transaction (for signing onlu)
// If it's full, it makes your transaction (for verification in most cases,
// but also for signing when breaking the channel)
// Index is used to set nlocktime for state hints.
// fee and op_csv timeout are currently hardcoded, make those parameters later.
// also returns the script preimage for later spending.
func (q *Qchan) BuildStateTx(mine bool) (*wire.MsgTx, error) {
	if q == nil {
		return nil, fmt.Errorf("BuildStateTx: nil chan")
	}
	// sanity checks
	s := q.State // use it a lot, make shorthand variable
	if s == nil {
		return nil, fmt.Errorf("channel (%d,%d) has no state", q.KeyGen.Step[3], q.KeyGen.Step[4])
	}
	// if delta is non-zero, something is wrong.
	if s.Delta != 0 {
		return nil, fmt.Errorf(
			"BuildStateTx: delta is %d (expect 0)", s.Delta)
	}
	var fancyAmt, pkhAmt int64   // output amounts
	var revPub, timePub [33]byte // pubkeys
	var pkhPub [33]byte          // the simple output's pub key hash
	fee := int64(5000)           // fixed fee for now
	delay := uint16(5)           // fixed CSV delay for now
	// delay is super short for testing.

	// Both received and self-generated elkpoints are needed
	// Here generate the elk point we give them (we know the scalar; they don't)
	theirElkPointR, theirElkPointT, err := q.MakeTheirCurElkPoints()
	if err != nil {
		return nil, err
	}
	// the PKH clear refund also has elkrem points added to mask the PKH.
	// this changes the txouts at each state to blind sorceror better.
	if mine { // build MY tx (to verify) (unless breaking)
		// My tx that I store.  They get funds unencumbered.
		// SH pubkeys are our base points plus the elk point we give them
		revPub = AddPubs(q.TheirHAKDBase, theirElkPointR)
		timePub = AddPubs(q.MyHAKDBase, theirElkPointT)

		pkhPub = AddPubs(q.TheirRefundPub, s.ElkPointR) // my received elkpoint
		pkhAmt = (q.Value - s.MyAmt) - fee
		fancyAmt = s.MyAmt - fee

		fmt.Printf("\t refund base %x, elkpointR %x\n", q.TheirRefundPub, s.ElkPointR)
	} else { // build THEIR tx (to sign)
		// Their tx that they store.  I get funds unencumbered.

		// SH pubkeys are our base points plus the received elk point
		revPub = AddPubs(q.MyHAKDBase, s.ElkPointR)
		timePub = AddPubs(q.TheirHAKDBase, s.ElkPointT)
		fancyAmt = (q.Value - s.MyAmt) - fee

		// PKH output
		pkhPub = AddPubs(q.MyRefundPub, theirElkPointR) // their (sent) elk point
		pkhAmt = s.MyAmt - fee
		fmt.Printf("\trefund base %x, elkpointR %x\n", q.MyRefundPub, theirElkPointR)
	}

	// now that everything is chosen, build fancy script and pkh script
	fancyScript, _ := CommitScript2(revPub, timePub, delay)
	pkhScript := DirectWPKHScript(pkhPub) // p2wpkh-ify

	fmt.Printf("> made SH script, state %d\n", s.StateIdx)
	fmt.Printf("\t revPub %x timeout pub %x \n", revPub, timePub)
	fmt.Printf("\t script %x ", fancyScript)

	fancyScript = P2WSHify(fancyScript) // p2wsh-ify

	fmt.Printf("\t scripthash %x\n", fancyScript)

	// create txouts by assigning amounts
	outFancy := wire.NewTxOut(fancyAmt, fancyScript)
	outPKH := wire.NewTxOut(pkhAmt, pkhScript)

	fmt.Printf("\tcombined refund %x, pkh %x\n", pkhPub, outPKH.PkScript)

	// make a new tx
	tx := wire.NewMsgTx()
	// add txouts
	tx.AddTxOut(outFancy)
	tx.AddTxOut(outPKH)
	// add unsigned txin
	tx.AddTxIn(wire.NewTxIn(&q.Op, nil, nil))
	// set index hints
	var x uint64
	if s.StateIdx > 0 { // state 0 and 1 can't use xor'd elkrem... fix this?
		x = q.GetElkZeroOffset()
		if x >= 1<<48 {
			return nil, fmt.Errorf("BuildStateTx elkrem error, x= %x", x)
		}
	}
	SetStateIdxBits(tx, s.StateIdx, x)

	// sort outputs
	txsort.InPlaceSort(tx)
	return tx, nil
}

func DirectWPKHScript(pub [33]byte) []byte {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0).AddData(btcutil.Hash160(pub[:]))
	b, _ := builder.Script()
	return b
}

// CommitScript2 doesn't use hashes, but a modified pubkey.
// To spend from it, push your sig.  If it's time-based,
// you have to set the txin's sequence.
func CommitScript2(RKey, TKey [33]byte, delay uint16) ([]byte, error) {
	builder := txscript.NewScriptBuilder()

	builder.AddOp(txscript.OP_DUP)
	builder.AddData(RKey[:])
	builder.AddOp(txscript.OP_CHECKSIG)

	builder.AddOp(txscript.OP_NOTIF)

	builder.AddData(TKey[:])
	builder.AddOp(txscript.OP_CHECKSIGVERIFY)
	builder.AddInt64(int64(delay))
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)

	builder.AddOp(txscript.OP_ENDIF)

	return builder.Script()
}

// FundMultiOut creates a TxOut for the funding transaction.
// Give it the two pubkeys and it'll give you the p2sh'd txout.
// You don't have to remember the p2sh preimage, as long as you remember the
// pubkeys involved.
func FundTxOut(pubA, puB [33]byte, amt int64) (*wire.TxOut, error) {
	if amt < 0 {
		return nil, fmt.Errorf("Can't create FundTx script with negative coins")
	}
	scriptBytes, _, err := FundTxScript(pubA, puB)
	if err != nil {
		return nil, err
	}
	scriptBytes = P2WSHify(scriptBytes)

	return wire.NewTxOut(amt, scriptBytes), nil
}

// FundMultiPre generates the non-p2sh'd multisig script for 2 of 2 pubkeys.
// useful for making transactions spending the fundtx.
// returns a bool which is true if swapping occurs.
func FundTxScript(aPub, bPub [33]byte) ([]byte, bool, error) {
	var swapped bool
	if bytes.Compare(aPub[:], bPub[:]) == -1 { // swap to sort pubkeys if needed
		aPub, bPub = bPub, aPub
		swapped = true
	}
	bldr := txscript.NewScriptBuilder()
	// Require 1 signatures, either key// so from both of the pubkeys
	bldr.AddOp(txscript.OP_2)
	// add both pubkeys (sorted)
	bldr.AddData(aPub[:])
	bldr.AddData(bPub[:])
	// 2 keys total.  In case that wasn't obvious.
	bldr.AddOp(txscript.OP_2)
	// Good ol OP_CHECKMULTISIG.  Don't forget the zero!
	bldr.AddOp(txscript.OP_CHECKMULTISIG)
	// get byte slice
	pre, err := bldr.Script()
	return pre, swapped, err
}

// the scriptsig to put on a P2SH input.  Sigs need to be in order!
func SpendMultiSigWitStack(pre, sigA, sigB []byte) [][]byte {

	witStack := make([][]byte, 4)

	witStack[0] = nil // it's not an OP_0 !!!! argh!
	witStack[1] = sigA
	witStack[2] = sigB
	witStack[3] = pre

	return witStack
}

func P2WSHify(scriptBytes []byte) []byte {
	bldr := txscript.NewScriptBuilder()
	bldr.AddOp(txscript.OP_0)
	wsh := fastsha256.Sum256(scriptBytes)
	bldr.AddData(wsh[:])
	b, _ := bldr.Script() // ignore script errors
	return b
}
