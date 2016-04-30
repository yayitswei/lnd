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
	// high 3 bytes are in sequence, low 3 bytes are in time
	seqMask  = 0xff000000 // assert high byte
	timeMask = 0x21000000 // 1987 to 1988

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

// IsClosed tells you if the channel is close (true) or still open (false)
// nil channels are considered closed but really shouldn't be happening.
func (q *Qchan) IsClosed() bool {
	if q == nil {
		return true
	}
	var empty wire.ShaHash
	if q.SpendTxid.IsEqual(&empty) {
		return false
	}
	return true
}

// GetStateIdxFromTx returns the state index from a commitment transaction.
// No errors; returns 0 if there is no retrievable index.
func GetStateIdxFromTx(tx *wire.MsgTx) uint64 {
	if tx == nil {
		//		fmt.Printf("nil tx\n")
		return 0
	}
	if len(tx.TxIn) != 1 {
		//		fmt.Printf("%d txins\n", len(tx.TxIn))
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

	return seqBits<<24 | timeBits
}

// SetStateIdxBits modifies the tx in place, setting the sequence and locktime
// fields to indicate the given state index.
func SetStateIdxBits(tx *wire.MsgTx, idx uint64) error {
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

	// high 24 bits sequence, low 24 bits locktime
	seqBits := uint32(idx >> 24)
	timeBits := uint32(idx & 0x00ffffff)

	tx.TxIn[0].Sequence = seqBits | seqMask
	tx.LockTime = timeBits | timeMask

	return nil
}

// ChannelInfo prints info about a channel.
func (t *TxStore) QchanInfo(q *Qchan) error {
	// display txid instead of outpoint because easier to copy/paste
	fmt.Printf("CHANNEL %s h:%d (%d,%d) cap: %d\n",
		q.Op.Hash.String(), q.AtHeight, q.PeerIdx, q.KeyIdx, q.Value)
	fmt.Printf("\tPUB mine:%x them:%x REFUND mine:%x them:%x\n",
		q.MyPub[:4], q.TheirPub[:4], q.MyRefundAdr[:4], q.TheirRefundAdr[:4])
	if q.State == nil {
		fmt.Printf("\t no valid state data\n")
	} else {
		fmt.Printf("\tSTATE HAKD:%x prevHAKD:%x stateidx:%d mine:%d them:%d\n",
			q.State.MyHAKDPub[:4], q.State.MyPrevHAKDPub[:4],
			q.State.StateIdx, q.State.MyAmt, q.Value-q.State.MyAmt)
		fmt.Printf("\telkrem receiver @%d\n", q.ElkRcv.UpTo())
	}

	if !q.IsClosed() { // still open, finish here
		return nil
	}
	// closed so get the spending tx
	spendTx, err := t.GetTx(&q.SpendTxid)
	if err != nil {
		return err
	}
	fmt.Printf("\tCLOSED. Spent by: %s", spendTx.TxSha().String())
	// if nlocktime is outside this range, we assume it was cooperatively
	// closed, so no further action is needed.
	txIdx := GetStateIdxFromTx(spendTx)

	if txIdx == 0 {
		fmt.Printf(" COOP\n")
		return nil
	}

	// figure out who broke it
	if len(spendTx.TxOut) != 2 {
		return fmt.Errorf("break TX has %d outputs?!?", len(spendTx.TxOut))
	}

	if bytes.Equal(spendTx.TxOut[0].PkScript[2:22], q.TheirRefundAdr[:]) ||
		bytes.Equal(spendTx.TxOut[1].PkScript[2:22], q.TheirRefundAdr[:]) {
		fmt.Printf(" non-coop by me.\n")
	} else {
		fmt.Printf(" non-coop by them\n")
		// detect bad state
		if txIdx != q.State.StateIdx {
			fmt.Printf("\tINVALID CHANNEL BREAK! State %d but tx state %d\n",
				q.State.StateIdx, txIdx)
		} else {
			fmt.Printf("\tchannel close OK, state %d, tx state %d\n",
				q.State.StateIdx, txIdx)
		}
	}
	return nil
}

// RecoverTx produces the recovery transaction to get all the money if they broadcast
// an old state which they invalidated.
// This function assumes a recovery is possible; if it can't construct the right
// keys and scripts it will return an error.
func (t *TxStore) RecoverTx(q *Qchan) (*wire.MsgTx, error) {
	// load spending tx
	spendTx, err := t.GetTx(&q.SpendTxid)
	if err != nil {
		return nil, err
	}
	if len(spendTx.TxOut) != 2 {
		return nil, fmt.Errorf("spend tx has %d outputs, can't sweep",
			len(spendTx.TxOut))
	}
	txIdx := GetStateIdxFromTx(spendTx)
	if txIdx == 0 {
		return nil, fmt.Errorf("no hint, can't recover")
	}

	// outpoint we're trying to recover
	op := wire.NewOutPoint(&q.SpendTxid, 0)
	shOut := new(wire.TxOut)

	// identify sh output
	if len(spendTx.TxOut[0].PkScript) > 30 {
		shOut = spendTx.TxOut[0]
	} else {
		shOut = spendTx.TxOut[1]
		op.Index = 1
	}

	// if hinted state is greater than elkrem state we can't recover
	if txIdx > q.ElkRcv.UpTo() {
		return nil, fmt.Errorf("tx at state %d but elkrem only goes to %d",
			txIdx, q.ElkRcv.UpTo())
	}

	// delay will be a channel-wide variable later.
	delay := uint32(5)
	var preScript []byte
	// build shOut script

	elk, err := q.ElkRcv.AtIndex(txIdx)
	if err != nil {
		return nil, err
	}

	// get private signing key
	priv := t.GetFundPrivkey(q.PeerIdx, q.KeyIdx)
	// modify private key
	PrivKeyAddBytes(priv, elk.Bytes())

	// serialize pubkey part for script generation
	var HAKDpubArr [33]byte
	copy(HAKDpubArr[:], priv.PubKey().SerializeCompressed())

	// now that everything is chosen, build fancy script and pkh script
	preScript, _ = CommitScript2(HAKDpubArr, q.TheirPub, delay)
	fancyScript := P2WSHify(preScript) // p2wsh-ify
	fmt.Printf("prescript: %x\np2wshd: %x\n", preScript, fancyScript)
	if !bytes.Equal(fancyScript, shOut.PkScript) {
		return nil, fmt.Errorf("script hash mismatch, generated %x expect %x",
			fancyScript, shOut.PkScript)
	}

	// build tx and sign.
	sweepTx := wire.NewMsgTx()
	changeOut, err := t.NewChangeOut(0)
	if err != nil {
		return nil, err
	}
	changeOut.Value = shOut.Value - 5000 // fixed fee for now
	sweepTx.AddTxOut(changeOut)

	// add unsigned input
	sweepIn := wire.NewTxIn(op, nil, nil)
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
		return nil, err
	}

	tx, err := q.BuildStateTx(theirHAKDpub)
	if err != nil {
		return nil, err
	}

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
	// copy here because... otherwise I get unexpected fault address 0x...
	theirSig := make([]byte, len(q.State.sig)+1)
	copy(theirSig, q.State.sig)
	theirSig[len(theirSig)-1] = byte(txscript.SigHashAll)

	fmt.Printf("made mysig: %x theirsig: %x\n", mySig, theirSig)
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
		opcodes, hCache, txscript.SigHashAll, tx, 0, q.Value)

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
	// add txouts
	tx.AddTxOut(outFancy)
	tx.AddTxOut(outPKH)
	// add unsigned txin
	tx.AddTxIn(wire.NewTxIn(&q.Op, nil, nil))
	// set index hints
	SetStateIdxBits(tx, s.StateIdx)

	// sort outputs
	txsort.InPlaceSort(tx)
	return tx, nil
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

/* old script2, need to push a 1 or 0 to select
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
/* uglier, need dup and drop...
builder.AddOp(txscript.OP_DUP)
builder.AddData(TKey[:])
builder.AddOp(txscript.OP_CHECKSIG)
builder.AddOp(txscript.OP_IF)
builder.AddOp(txscript.OP_DROP)
builder.AddInt64(int64(delay))
builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
builder.AddOp(txscript.OP_ELSE)
builder.AddData(RKey[:])
builder.AddOp(txscript.OP_CHECKSIG)
builder.AddOp(txscript.OP_ENDIF)
*/

// CommitScript2 doesn't use hashes, but a modified pubkey.
// To spend from it, push your sig.  If it's time-based,
// you have to set the txin's sequence.
func CommitScript2(RKey, TKey [33]byte, delay uint32) ([]byte, error) {
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
