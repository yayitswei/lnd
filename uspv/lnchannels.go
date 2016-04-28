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

const (
	timeHintMask = 0x1fffffff // 29 bits asserted

	MSGID_PUBREQ  = 0x30
	MSGID_PUBRESP = 0x31

	MSGID_CHANDESC = 0x32
	MSGID_CHANACK  = 0x3B

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

	Utxo                   // S underlying utxo data
	SpendTxid wire.ShaHash // S txid of transaction destroying channel

	MyPub    [33]byte // D my channel specific pubkey
	TheirPub [33]byte // S their channel specific pubkey

	PeerIdx   uint32   // D local unique index of peer.  derived from place in db.
	PeerPubId [33]byte // D useful for quick traverse of db

	TheirRefundAdr [20]byte // S their address for when you break
	MyRefundAdr    [20]byte // D my refund address when they break

	// Elkrem is used for revoking state commitments
	ElkSnd *elkrem.ElkremSender   // D derived from channel specific key
	ElkRcv *elkrem.ElkremReceiver // S stored in db

	State *StatCom // S state of channel
}

// StatComs are State Commitments.
type StatCom struct {
	StateIdx uint64 // this is the n'th state commitment

	MyAmt int64 // my channel allocation
	// their Amt is the utxo.Value minus this
	Delta int32 // fun amount in-transit; is negative for the pusher

	// Homomorphic Adversarial Key Derivation public keys (HAKD)
	MyHAKDPub     [33]byte // saved to disk
	MyPrevHAKDPub [33]byte // When you haven't gotten their revocation elkrem yet.

	sig []byte // Counterparty's signature (for StatCom tx)
	// don't write to sig directly; only overwrite via

	// note sig can be nil during channel creation. if stateIdx isn't 0,
	// sig should have a sig.
	// only one sig is ever stored, to prevent broadcasting the wrong tx.
	// could add a mutex here... maybe will later.
}

var (
	Hash88 = [20]byte{0xd7, 0x9f, 0x49, 0x37, 0x1f, 0xb5, 0xd9, 0xe7, 0x92, 0xf0, 0x42, 0x66, 0x4c, 0xd6, 0x89, 0xd5, 0x0e, 0x3d, 0xcf, 0x03}
)

// MakeHAKDPubkey generates the HAKD pubkey to send out or everify sigs.
// leaves channel struct the same; returns HAKD pubkey.
func (q *Qchan) MakeTheirHAKDPubkey() ([33]byte, error) {
	var HAKDpubArr [33]byte

	if q == nil || q.ElkSnd == nil { // can't do anything
		return HAKDpubArr, fmt.Errorf("can't access elkrem")
	}
	// use the elkrem sender at state's index.  not index + 1
	// (you revoke index - 1)
	elk, err := q.ElkSnd.AtIndex(q.State.StateIdx)
	if err != nil {
		return HAKDpubArr, err
	}
	// deserialize their channel pubkey
	HAKDPub, err := btcec.ParsePubKey(q.TheirPub[:], btcec.S256())
	if err != nil {
		return HAKDpubArr, err
	}
	// add your elkrem to the pubkey
	PubKeyAddBytes(HAKDPub, elk.Bytes())

	copy(HAKDpubArr[:], HAKDPub.SerializeCompressed())

	return HAKDpubArr, nil
}

// IngestElkrem takes in an elkrem hash, performing 2 checks:
// that it produces the proper HAKD key, and that it fits into the elkrem tree.
// if both of these are the case it updates the channel state, removing the
// revoked HAKD. If either of these checks fail, and definitely the second one
// fails, I'm pretty sure the channel is not recoverable and needs to be closed.
func (q *Qchan) IngestElkrem(elk *wire.ShaHash) error {
	if elk == nil {
		return fmt.Errorf("IngestElkrem: nil hash")
	}

	// first verify if the elkrem produces the previous HAKD's PUBLIC key.
	// We don't actually use the private key operation here, because we can
	// do the same operation on our pubkey that they did, and we have faith
	// in the mysterious power of abelian group homomorphisms that the private
	// key modification will also work.

	// first verify the elkrem insertion (this only performs checks 1/2 the time, so
	// 1/2 the time it'll work even if the elkrem is invalid, oh well)
	err := q.ElkRcv.AddNext(elk)
	if err != nil {
		return err
	}
	fmt.Printf("ingested hash, receiver now has up to %d\n", q.ElkRcv.UpTo())

	// if this is state 1, this is elkrem 0 and we can stop here.
	// there's nothing to revoke. (state 0, also? but that would imply
	// elkrem -1 which isn't a thing... so fail in that case.)
	if q.State.StateIdx == 1 {
		return nil
	}

	// make my channel pubkey array into a pubkey
	derivedPub, err := btcec.ParsePubKey(q.MyPub[:], btcec.S256())
	if err != nil {
		return err
	}

	// add elkrem to my pubkey
	PubKeyAddBytes(derivedPub, elk.Bytes())

	// re-serialize to compare
	var derivedArr, empty [33]byte
	copy(derivedArr[:], derivedPub.SerializeCompressed())

	// see if it matches my previous HAKD pubkey
	if derivedArr != q.State.MyPrevHAKDPub {
		// didn't match, the whole channel is borked.
		return fmt.Errorf("Provided elk doesn't create HAKD pub %x! Need to close",
			q.State.MyPrevHAKDPub)
	}

	// it did match, so we can clear the previous HAKD pub
	q.State.MyPrevHAKDPub = empty

	return nil
}

// SignBreak signs YOUR tx, which you already have a sig for
func (t TxStore) SignBreakTx(q *Qchan) (*wire.MsgTx, error) {
	// generate their HAKDpub.  Be sure you haven't revoked it!
	theirHAKDpub, err := q.MakeTheirHAKDPubkey()
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return nil, err
	}

	tx, err := q.BuildStateTx(theirHAKDpub)

	// make hash cache for this tx
	hCache := txscript.NewTxSigHashes(tx)

	// generate script preimage (keep track of key order)
	pre, swap, err := FundTxScript(q.MyPub[:], q.TheirPub[:])
	if err != nil {
		return nil, err
	}

	// get private signing key
	priv := t.GetFundPrivkey(q.PeerIdx, q.KeyIdx)

	// generate sig.
	mySig, err := txscript.RawTxInWitnessSignature(
		tx, hCache, 0, q.Value, pre, txscript.SigHashAll, priv)

	// put the sighash all byte on the end of their signature
	theirSig := append(q.State.sig, byte(txscript.SigHashAll))

	// add sigs to the witness stack
	if swap {
		tx.TxIn[0].Witness = SpendMultiSigWitStack(pre, theirSig, mySig)
	} else {
		tx.TxIn[0].Witness = SpendMultiSigWitStack(pre, mySig, theirSig)
	}
	return tx, nil
}

// SignNextState generates your signature for their state. (usually)
func (t TxStore) SignState(q *Qchan) ([]byte, error) {
	var empty [33]byte
	// build transaction for next state
	tx, err := q.BuildStateTx(empty) // generally their tx, as I'm signing
	if err != nil {
		return nil, err
	}

	// make hash cache for this tx
	hCache := txscript.NewTxSigHashes(tx)

	// generate script preimage (ignore key order)
	pre, _, err := FundTxScript(q.MyPub[:], q.TheirPub[:])
	if err != nil {
		return nil, err
	}

	// get private signing key
	priv := t.GetFundPrivkey(q.PeerIdx, q.KeyIdx)

	// generate sig.
	sig, err := txscript.RawTxInWitnessSignature(
		tx, hCache, 0, q.Value, pre, txscript.SigHashAll, priv)
	// truncate sig (last byte is sighash type, always sighashAll)
	sig = sig[:len(sig)-1]

	fmt.Printf("____ sig creation for channel (%d,%d):\n", q.PeerIdx, q.KeyIdx)
	fmt.Printf("\tinput %s\n", tx.TxIn[0].PreviousOutPoint.String())
	fmt.Printf("\toutput 0: %x %d\n", tx.TxOut[0].PkScript, tx.TxOut[0].Value)
	fmt.Printf("\toutput 1: %x %d\n", tx.TxOut[1].PkScript, tx.TxOut[1].Value)
	fmt.Printf("\tstate %d myamt: %d theiramt: %d\n", q.State.StateIdx, q.State.MyAmt, q.Value-q.State.MyAmt)
	fmt.Printf("\tmy HAKD pub: %x their HAKD pub: %x sig: %x\n", q.State.MyHAKDPub[:4], empty[:4], sig)

	return sig, nil
}

// VerifySig verifies their signature for your next state.
// it also saves the sig if it's good.
// do bool, error or just error?  Bad sig is an error I guess.
// for verifying signature, always use theirHAKDpub, so generate & populate within
// this function.
func (q *Qchan) VerifySig(sig []byte) error {
	theirHAKDpub, err := q.MakeTheirHAKDPubkey()
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return err
	}

	// ALWAYS my tx, ALWAYS their HAKD when I'm verifying.
	tx, err := q.BuildStateTx(theirHAKDpub)
	if err != nil {
		return err
	}

	// generate fund output script preimage (ignore key order)
	pre, _, err := FundTxScript(q.MyPub[:], q.TheirPub[:])
	if err != nil {
		return err
	}
	// parse out opcodes... I don't think this does anything but this is what
	// calc witness sighash wants.
	opcodes, err := txscript.ParseScript(pre)
	if err != nil {
		return err
	}

	hCache := txscript.NewTxSigHashes(tx)
	// always sighash all
	hash := txscript.CalcWitnessSignatureHash(
		opcodes, hCache, txscript.SigHashAll, tx, int(q.Op.Index), q.Value)

	// sig is pre-truncated; last byte for sighashtype is always sighashAll
	pSig, err := btcec.ParseDERSignature(sig, btcec.S256())
	if err != nil {
		return err
	}
	theirPubKey, err := btcec.ParsePubKey(q.TheirPub[:], btcec.S256())
	if err != nil {
		return err
	}
	fmt.Printf("____ sig verification for channel (%d,%d):\n", q.PeerIdx, q.KeyIdx)
	fmt.Printf("\tinput %s\n", tx.TxIn[0].PreviousOutPoint.String())
	fmt.Printf("\toutput 0: %x %d\n", tx.TxOut[0].PkScript, tx.TxOut[0].Value)
	fmt.Printf("\toutput 1: %x %d\n", tx.TxOut[1].PkScript, tx.TxOut[1].Value)
	fmt.Printf("\tstate %d myamt: %d theiramt: %d\n", q.State.StateIdx, q.State.MyAmt, q.Value-q.State.MyAmt)
	fmt.Printf("\tmy HAKD pub: %x their HAKD pub: %x sig: %x\n", q.State.MyHAKDPub[:4], theirHAKDpub[:4], sig)

	worked := pSig.Verify(hash, theirPubKey)
	if !worked {
		return fmt.Errorf("Their sig was no good!!!!!111")
	}

	// copy signature, overwriting old signature.
	q.State.sig = sig

	return nil
}

func (q *Qchan) SignBreak() error {
	return nil
}

// BuildStateTx constructs and returns a state tx.  As simple as I can make it.
// This func just makes the tx with data from State in ram, and HAKD key arg
// Delta should always be 0 when making this tx.
// It decides whether to make THEIR tx or YOUR tx based on the HAKD pubkey given --
// if it's zero, then it makes their transaction (for signing onlu)
// If it's zero, it makes your transaction (for verification in most cases,
// but also for signing when breaking the channel)
// Index is used to set nlocktime for state hints.
// fee and op_csv timeout are currently hardcoded, make those parameters later.
func (q *Qchan) BuildStateTx(theirHAKDpub [33]byte) (*wire.MsgTx, error) {
	// sanity checks
	s := q.State // use it a lot, make shorthand variable
	if s == nil {
		return nil, fmt.Errorf("channel (%d,%d) has no state", q.PeerIdx, q.KeyIdx)
	}
	// if delta is non-zero, something is wrong.
	if s.Delta != 0 {
		return nil, fmt.Errorf(
			"BuildStateTx: delta is %d (expect 0)", s.Delta)
	}
	//	if q.MyPub == nil || q.TheirPub == nil {
	//		return nil, fmt.Errorf("BuildStateTx: chan pubkey nil")
	//	}

	var empty [33]byte

	var fancyAmt, pkhAmt int64   // output amounts
	var revPub, timePub [33]byte // pubkeys
	var pkhAdr [20]byte          // the simple output's pub key hash
	fee := int64(5000)           // fixed fee for now
	delay := uint32(5)           // fixed CSV delay for now
	// delay is super short for testing.

	if theirHAKDpub == empty { // TheirHAKDPub is empty; build THEIR tx (to sign)
		// Their tx that they store.  I get funds unencumbered.
		pkhAdr = q.MyRefundAdr
		pkhAmt = s.MyAmt - fee

		timePub = q.TheirPub // these are their funds, but they have to wait
		revPub = s.MyHAKDPub // if they're given me the elkrem, it's mine
		fancyAmt = (q.Value - s.MyAmt) - fee
	} else { // theirHAKDPub is full; build MY tx (to verify) (unless breaking)
		// My tx that I store.  They get funds unencumbered.
		pkhAdr = q.TheirRefundAdr
		pkhAmt = (q.Value - s.MyAmt) - fee

		timePub = q.MyPub     // these are my funds, but I have to wait
		revPub = theirHAKDpub // I can revoke by giving them the elkrem
		fancyAmt = s.MyAmt - fee
	}

	// now that everything is chosen, build fancy script and pkh script
	fancyScript, _ := CommitScript2(revPub, timePub, delay)
	pkhScript := DirectWPKHScript(pkhAdr) // p2wpkh-ify
	fancyScript = P2WSHify(fancyScript)   // p2wsh-ify

	// create txouts by assigning amounts
	outFancy := wire.NewTxOut(fancyAmt, fancyScript)
	outPKH := wire.NewTxOut(pkhAmt, pkhScript)

	// make a new tx
	tx := wire.NewMsgTx()
	tx.LockTime = 500000000 + uint32(s.StateIdx&0x1fffffff)
	// add txouts
	tx.AddTxOut(outFancy)
	tx.AddTxOut(outPKH)
	// add unsigned txin
	tx.AddTxIn(wire.NewTxIn(&q.Op, nil, nil))

	txsort.InPlaceSort(tx)
	return tx, nil
	return nil, nil
}

func DirectWPKHScript(pkh [20]byte) []byte {
	builder := txscript.NewScriptBuilder()
	b, _ := builder.AddOp(txscript.OP_0).AddData(pkh[:]).Script()
	return b
}

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

/* old script2
builder.AddOp(txscript.OP_IF)
builder.AddInt64(int64(delay))
builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
builder.AddOp(txscript.OP_DROP)
builder.AddData(TKey[:])
builder.AddOp(txscript.OP_ELSE)
builder.AddData(RKey[:])
builder.AddOp(txscript.OP_ENDIF)
builder.AddOp(txscript.OP_CHECKSIG)
*/

// CommitScript2 doesn't use hashes, but a modified pubkey.
// To spend from it, push your sig.  If it's time-based,
// you have to set the txin's sequence.
func CommitScript2(RKey, TKey [33]byte, delay uint32) ([]byte, error) {
	builder := txscript.NewScriptBuilder()

	builder.AddData(TKey[:])
	builder.AddOp(txscript.OP_CHECKSIG)
	builder.AddOp(txscript.OP_IF)
	builder.AddInt64(int64(delay))
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_ELSE)
	builder.AddData(RKey[:])
	builder.AddOp(txscript.OP_CHECKSIG)
	builder.AddOp(txscript.OP_ENDIF)

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

/*----- serialization for StatCom ------- */
/*
bytes   desc   ends at
1	len			1
8	StateIdx		9
8	MyAmt		17
4	Delta		21
33	MyRev		54
33	MyPrevRev	87
70?	Sig			157
... to 131 bytes, ish.

note that sigs are truncated and don't have the sighash type byte at the end.

their rev hash can be derived from the elkrem sender
and the stateidx.  hash160(elkremsend(sIdx)[:16])

*/

// ToBytes turns a StatCom into 106ish bytes
func (s *StatCom) ToBytes() ([]byte, error) {
	var buf bytes.Buffer
	var err error

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
	// write 4 byte delta.  At steady state it's 0.
	err = binary.Write(&buf, binary.BigEndian, s.Delta)
	if err != nil {
		return nil, err
	}
	// write 33 byte my revocation pubkey
	_, err = buf.Write(s.MyHAKDPub[:])
	if err != nil {
		return nil, err
	}
	// write 33 byte my previous revocation hash
	// at steady state it's 0s.
	_, err = buf.Write(s.MyPrevHAKDPub[:])
	if err != nil {
		return nil, err
	}
	// write their sig
	_, err = buf.Write(s.sig)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// StatComFromBytes turns 160 ish bytes into a StatCom
// it might be only 86 bytes because there is no sig (first save)
func StatComFromBytes(b []byte) (*StatCom, error) {
	var s StatCom
	if len(b) < 80 || len(b) > 170 {
		return nil, fmt.Errorf("StatComFromBytes got %d bytes, expect around 131\n",
			len(b))
	}
	buf := bytes.NewBuffer(b)
	// read 8 byte state index
	err := binary.Read(buf, binary.BigEndian, &s.StateIdx)
	if err != nil {
		return nil, err
	}
	// read 8 byte amount of my allocation in the channel
	err = binary.Read(buf, binary.BigEndian, &s.MyAmt)
	if err != nil {
		return nil, err
	}
	// read 4 byte delta.
	err = binary.Read(buf, binary.BigEndian, &s.Delta)
	if err != nil {
		return nil, err
	}
	// read 33 byte HAKD pubkey
	copy(s.MyHAKDPub[:], buf.Next(33))
	// read 33 byte previous HAKD pubkey
	copy(s.MyPrevHAKDPub[:], buf.Next(33))
	// the rest is their sig
	s.sig = buf.Bytes()

	return &s, nil
}

/*----- serialization for QChannels ------- */

/* Qchan serialization:
(it's just a utxo with their pubkey)
bytes   desc   at offset

53	utxo		0
33	thrpub	53
20	thrref	86
32	spendTx	106

length 138

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
	_, err = buf.Write(q.TheirPub[:])
	if err != nil {
		return nil, err
	}
	// write their refund address pubkeyhash
	_, err = buf.Write(q.TheirRefundAdr[:])
	if err != nil {
		return nil, err
	}
	// write txid of transaction spending this
	// (this is mostly 00 so kindof a waste to serialize here...
	_, err = buf.Write(q.SpendTxid.Bytes())
	if err != nil {
		return nil, err
	}

	// done
	return buf.Bytes(), nil
}

// QchanFromBytes turns bytes into a Qchan.
// the first 53 bytes are the utxo, then next 33 is the pubkey, then their pkh.
// then finally txid of spending transaction
func QchanFromBytes(b []byte) (Qchan, error) {
	var q Qchan

	if len(b) < 138 {
		return q, fmt.Errorf("Got %d bytes for MultiOut, expect 138", len(b))
	}

	u, err := UtxoFromBytes(b[:53])
	if err != nil {
		return q, err
	}

	q.Utxo = u // assign the utxo

	copy(q.TheirPub[:], b[53:86])
	if err != nil {
		return q, err
	}
	copy(q.TheirRefundAdr[:], b[86:106])
	// spend txid (can be 00)
	err = q.SpendTxid.SetBytes(b[106:])
	if err != nil {
		return q, err
	}

	return q, nil
}
