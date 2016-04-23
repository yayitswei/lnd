package uspv

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/lightningnetwork/lnd/elkrem"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/txsort"
	"github.com/btcsuite/fastsha256"
)

// Uhh, quick channel.  For now.  Once you get greater spire it upgrades to
// a full channel that can do everything.
type Qchan struct {
	// S for stored (on disk), D for derived

	Utxo                      // S underlying utxo data
	MyPub    *btcec.PublicKey // D my channel specific pubkey
	TheirPub *btcec.PublicKey // S their channel specific pubkey

	PeerIdx uint32 // D local unique index of peer.  derived from place in db.

	TheirRefundAdr [20]byte // S their address for when you break
	MyRefundAdr    [20]byte // D my refund address when they break

	// Elkrem is used for revoking state commitments
	Elk elkrem.ElkremPair // S elkrem sender and receiver

	CurrentState *StatCom // S current state of channel
	NextState    *StatCom // D? temporary, next state of channel
}

// StatComs are State Commitments.
type StatCom struct {
	MyAmt int64 // my channel allocation
	// their Amt is the utxo.Value minus this

	StateIdx uint64 // this is the n'th state commitment

	TheirRevHash [20]byte // 16byte hash, preimage of which is needed to sweep.
	MyRevHash    [20]byte // the revoke hash I generate and send to them
	Sig          []byte   // Counterparty's signature (for StatCom tx)
}

var (
	Hash88 = [20]byte{0xd7, 0x9f, 0x49, 0x37, 0x1f, 0xb5, 0xd9, 0xe7, 0x92, 0xf0, 0x42, 0x66, 0x4c, 0xd6, 0x89, 0xd5, 0x0e, 0x3d, 0xcf, 0x03}
)

// ScriptAddress returns the *34* byte address of the outpoint.
// note that it's got the 0020 in front.  [2:] if you want to get rid of that.
//func (m *MultiOut) ScriptAddress() ([]byte, error) {
//	script, _, err := FundMultiPre(
//		m.MyPub.SerializeCompressed(), m.TheirPub.SerializeCompressed())
//	if err != nil {
//		return nil, err
//	}
//	return script, nil
//}

// SignNextState generates your signature for their next state.
// doesn't modify next state.
func (t TxStore) SignNextState(q *Qchan) ([]byte, error) {

	// build transaction for next state
	tx, err := q.BuildStateTx(false, true) // theirs, next
	if err != nil {
		return nil, err
	}

	// make hash cache for this tx
	hCache := txscript.NewTxSigHashes(tx)

	// generate script preimage (ignore key order)
	pre, _, err := FundTxScript(
		q.MyPub.SerializeCompressed(), q.TheirPub.SerializeCompressed())
	if err != nil {
		return nil, err
	}

	// get private signing key
	priv := t.GetFundPrivkey(q.PeerIdx, q.KeyIdx)

	// generate sig.
	sig, err := txscript.RawTxInWitnessSignature(
		tx, hCache, 0, q.Value, pre, txscript.SigHashAll, priv)

	return sig, nil
}

// VerifyNextState verifies their signature for your next state.
// it also saves the sig in the next state.
func (q *Qchan) VerifyNextState(sig []byte) error {
	return nil
}

func (q *Qchan) SignBreak() error {
	return nil
}

// NextStateTx constructs and returns the next state tx.
// mine == true makes the tx I receive sigs for and store, false
// makes the state I sign and send but dont store or broadcast.
func (q *Qchan) BuildStateTx(mine bool, next bool) (*wire.MsgTx, error) {
	var fancyAmt, pkhAmt int64            // output amounts
	var comHash [20]byte                  // commitment hash
	var hashPub, timePub *btcec.PublicKey // pubkeys
	var pkhAdr [20]byte                   // the simple output's pub key hash

	fee := int64(5000) // fixed fee for now

	if q.MyPub == nil || q.TheirPub == nil {
		return nil, fmt.Errorf("chan pubkey nil")
	}

	// this part chooses all the different amounts and hashes and stuff.
	// it's kindof tricky and dense! But it's as straightforward as it can be.
	if mine { // my tx. They're pkh; I'm time, they're hash
		hashPub = q.TheirPub
		timePub = q.MyPub
		pkhAdr = q.TheirRefundAdr
		if next { // use next state amts / hashes
			fancyAmt = q.NextState.MyAmt - fee
			pkhAmt = q.Value - q.NextState.MyAmt - fee
			comHash = q.NextState.MyRevHash
		} else { // use current state amts / hashes
			fancyAmt = q.CurrentState.MyAmt - fee
			pkhAmt = q.Value - q.CurrentState.MyAmt - fee
			comHash = q.CurrentState.MyRevHash
		}
	} else { // their tx. I'm pkh; I'm hash, they're time
		hashPub = q.MyPub
		timePub = q.TheirPub
		pkhAdr = q.MyRefundAdr
		if next {
			fancyAmt = q.Value - q.NextState.MyAmt - fee
			pkhAmt = q.NextState.MyAmt - fee
			comHash = q.NextState.TheirRevHash
		} else {
			fancyAmt = q.Value - q.CurrentState.MyAmt - fee
			pkhAmt = q.CurrentState.MyAmt - fee
			comHash = q.CurrentState.TheirRevHash
		}
	}

	// now that everything is chosen, build fancy script and pkh script
	fancyScript, _ := CommitScript(hashPub, timePub, comHash, 5)
	pkhScript := DirectWPKHScript(pkhAdr)

	// create txouts by assigning amounts
	outFancy := wire.NewTxOut(fancyAmt, fancyScript)
	outPKH := wire.NewTxOut(pkhAmt, pkhScript)

	// make a new tx
	tx := wire.NewMsgTx()
	// add txouts
	tx.AddTxOut(outFancy)
	tx.AddTxOut(outPKH)
	// add unsigned txin
	tx.AddTxIn(wire.NewTxIn(&q.Op, nil, nil))

	txsort.InPlaceSort(tx)
	return tx, nil
}

func DirectWPKHScript(pkh [20]byte) []byte {
	builder := txscript.NewScriptBuilder()
	b, _ := builder.AddOp(txscript.OP_0).AddData(pkh[:]).Script()
	return b
}

/*
func (q *Qchan) BuildStatComTx(mine bool, R [20]byte) (*wire.MsgTx, error) {
	// commitment is "mine" if I'm committing and sign; !mine if they sign.
	comTx := wire.NewMsgTx()

	// no sigscript, given separately to WitnessScript() as subscript
	fundIn := wire.NewTxIn(&s.FundPoint, nil, nil)
	comTx.AddTxIn(fundIn)

	TheirAmt := s.Cap - s.NextState.MyAmt

	var outPKH, outFancy *wire.TxOut
	if mine { // I'm committing to me getting my funds unencumbered
		pkh := btcutil.Hash160(s.MyPub.SerializeCompressed())
		wpkhScript := append([]byte{0x00, 0x14}, pkh...)
		outPKH = wire.NewTxOut(s.NextState.MyAmt, wpkhScript)
		// encumbered: they need time, I need a hash
		// only errors are 'non cannonical script' so ignore errors
		fancyScript, _ := commitScript(s.Expiry, s.MyPub, s.TheirPub, R)
		outFancy = wire.NewTxOut(TheirAmt, fancyScript)
	} else { // they're committing to getting their funds unencumbered
		pkh := btcutil.Hash160(s.TheirPub.SerializeCompressed())
		wpkhScript := append([]byte{0x00, 0x14}, pkh...)
		outPKH = wire.NewTxOut(TheirAmt, P2WSHify(wpkhScript))

		fancyScript, _ := commitScript(s.Expiry, s.TheirPub, s.MyPub, R)
		outFancy = wire.NewTxOut(s.NextState.MyAmt, fancyScript)
	}

	comTx.AddTxOut(outPKH)
	comTx.AddTxOut(outFancy)

	return comTx, nil
}
*/

// for testing: h160(0x88): d79f49371fb5d9e792f042664cd689d50e3dcf03

// commitScript constructs the public key script for the output on the
// commitment transaction paying to the "owner" of said commitment transaction.
// If the other party learns of the pre-image to the revocation hash, then they
// can claim all the settled funds in the channel, plus the unsettled funds.
// uses op_cltv
func CommitScript(HKey, TKey *btcec.PublicKey,
	revokeHash [20]byte, cltvDelay uint32) ([]byte, error) {

	// This script is spendable under two conditions: either the 'cltvtime'
	// has passed and T(ime)Key signs, or revokeHash's preimage is presented
	// and H(ash)Key signs.
	builder := txscript.NewScriptBuilder()

	// If the pre-image for the revocation hash is presented, then allow a
	// spend provided the proper signature.
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(revokeHash[:])
	builder.AddOp(txscript.OP_EQUAL)
	builder.AddOp(txscript.OP_IF)
	builder.AddData(HKey.SerializeCompressed())
	builder.AddOp(txscript.OP_ELSE)

	// Otherwise, we can re-claim our funds after CLTV time
	// 'csvTimeout' timeout blocks, and a valid signature.
	builder.AddInt64(int64(cltvDelay))
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_DROP)
	builder.AddData(TKey.SerializeCompressed())
	builder.AddOp(txscript.OP_ENDIF)
	builder.AddOp(txscript.OP_CHECKSIG)

	return builder.Script()
}

// FundMultiOut creates a TxOut for the funding transaction.
// Give it the two pubkeys and it'll give you the p2sh'd txout.
// You don't have to remember the p2sh preimage, as long as you remember the
// pubkeys involved.
func FundTxOut(pubA, puB []byte, amt int64) (*wire.TxOut, error) {
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
func FundTxScript(aPub, bPub []byte) ([]byte, bool, error) {
	if len(aPub) != 33 || len(bPub) != 33 {
		return nil, false, fmt.Errorf("Pubkey size error. Compressed pubkeys only")
	}
	var swapped bool
	if bytes.Compare(aPub, bPub) == -1 { // swap to sort pubkeys if needed
		aPub, bPub = bPub, aPub
		swapped = true
	}
	bldr := txscript.NewScriptBuilder()
	// Require 1 signatures, either key// so from both of the pubkeys
	bldr.AddOp(txscript.OP_2)
	// add both pubkeys (sorted)
	bldr.AddData(aPub)
	bldr.AddData(bPub)
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

// StatComs are State Commitments.
//type StatCom struct {
//	StateIdx uint64 // this is the n'th state commitment

//	MyAmt int64 // my channel allocation
//	// their Amt is the utxo.Value minus this

//	TheirRevHash [20]byte // 16byte hash, preimage of which is needed to sweep.
//	MyRevHash    [20]byte // the revoke hash I generate and send to them
//	Sig          []byte   // Counterparty's signature (for StatCom tx)
//}

/*----- serialization for StatCom ------- */
/*
bytes   desc   at offset
1	len			0
8	StateIdx		1
8	MyAmt		9
20	TheirRev		17
70?	Sig			37
... to 107 bytes, ish.

my rev hash can be derived from the elkrem sender
and the stateidx.  hash160(elkremsend(sIdx)[:16])

*/

// ToBytes turns a StatCom into 106ish bytes
func (s *StatCom) ToBytes() ([]byte, error) {
	var buf bytes.Buffer
	var err error

	// Don't have this for now... gets saved separately
	// write 1 byte length of this statcom
	// (needed because sigs are #()# variable length
	//	slen := uint8(len(s.Sig) + 36)
	//	err := buf.WriteByte(slen)
	//	if err != nil {
	//		return nil, err
	//	}

	// write 8 byte state index
	err = binary.Write(&buf, binary.BigEndian, s.StateIdx)
	if err != nil {
		return nil, err
	}
	// write 8 byte amount of my allocation in the channel
	err = binary.Write(&buf, binary.BigEndian, s.MyAmt)
	if err != nil {
		return nil, err
	}
	// write 20 byte their revocation hash
	_, err = buf.Write(s.TheirRevHash[:])
	if err != nil {
		return nil, err
	}
	// write their sig
	_, err = buf.Write(s.Sig)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// StatComFromBytes turns 106ish bytes into a StatCom
func StatComFromBytes(b []byte) (StatCom, error) {
	var s StatCom
	if len(b) < 100 || len(b) > 110 {
		return s, fmt.Errorf("StatComFromBytes got %d bytes, expect around 106\n",
			len(b))
	}
	buf := bytes.NewBuffer(b)
	// read 8 byte state index
	err := binary.Read(buf, binary.BigEndian, &s.StateIdx)
	if err != nil {
		return s, err
	}
	// read 8 byte amount of my allocation in the channel
	err = binary.Read(buf, binary.BigEndian, &s.MyAmt)
	if err != nil {
		return s, err
	}
	// read the 20 bytes of their revocation hash
	copy(s.TheirRevHash[:], buf.Next(20))
	// the rest is their sig
	s.Sig = buf.Bytes()

	return s, nil
}

/*----- serialization for QChannels ------- */

/* Qchan serialization:
(it's just a utxo with their pubkey)
bytes   desc   at offset

53	utxo		0
33	thrpub	53
20	thrref	86

done at 	106, then
statecom(current)
statecom(next)

peeridx is inferred from position in db.
*/

func (q *Qchan) ToBytes() ([]byte, error) {
	var buf bytes.Buffer
	// first serialize the utxo part
	uBytes, err := q.Utxo.ToBytes()
	if err != nil {
		return nil, err
	}
	// write that into the buffer first
	_, err = buf.Write(uBytes)
	if err != nil {
		return nil, err
	}

	// write 33 byte pubkey (theirs)
	_, err = buf.Write(q.TheirPub.SerializeCompressed())
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(q.TheirRefundAdr[:])
	if err != nil {
		return nil, err
	}
	// done
	return buf.Bytes(), nil
}

// MultiOutFromBytes turns bytes into a MultiOut.
// the first 53 bytes are the utxo, then next 33 is the pubkey
func QchanFromBytes(b []byte) (Qchan, error) {
	var q Qchan

	if len(b) < 106 {
		return q, fmt.Errorf("Got %d bytes for MultiOut, expect 86", len(b))
	}

	u, err := UtxoFromBytes(b[:53])
	if err != nil {
		return q, err
	}

	//	buf := bytes.NewBuffer(b[53:86])
	// will be 33, size checked up there

	q.Utxo = u // assign the utxo

	q.TheirPub, err = btcec.ParsePubKey(b[53:86], btcec.S256())
	if err != nil {
		return q, err
	}
	copy(q.TheirRefundAdr[:], b[86:106])
	return q, nil
}
