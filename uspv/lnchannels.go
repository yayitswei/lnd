package uspv

import (
	"bytes"
	"fmt"

	"github.com/lightningnetwork/lnd/elkrem"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/fastsha256"
)

// Uhh, quick channel.  For now.  Once you get greater spire it upgrades to
// a full channel that can do everything.
type Qchan struct {
	// S for stored (on disk), D for derived

	Utxo                      // S underlying utxo data
	MyPubx   *btcec.PublicKey // D my channel specific pubkey
	TheirPub *btcec.PublicKey // S their channel specific pubkey

	TheirRefundAdr [20]byte // S their address for when you break

	PeerIdx uint32 // D local unique index of peer.  derived from place in db.

	// Elkrem is used for revoking state commitments
	Elk elkrem.ElkremPair // S elkrem sender and receiver

	CurrentState *StatCom // S current state of channel
	NextState    *StatCom // D temporary, next state of channel
}

// StatComs are State Commitments.
type StatCom struct {
	MyAmt int64 // my channel allocation
	// their Amt is the utxo.Value minus this

	StateIdx uint64 // this is the n'th state commitment

	RevokeHash [16]byte // 16byte hash, preimage of which is needed to sweep.
	Sig        []byte   // Counterparty's signature (for StatCom tx)
}

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

// generate a signature for the next state
func (q *Qchan) SignNextState() error {
	return nil
}

// Verify their signature for the next state
func (q *Qchan) VerifyNextState(sig []byte) error {
	return nil
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

// commitScriptToSelf constructs the public key script for the output on the
// commitment transaction paying to the "owner" of said commitment transaction.
// If the other party learns of the pre-image to the revocation hash, then they
// can claim all the settled funds in the channel, plus the unsettled funds.
// Modified to use CLTV because CSV isn't in segnet yet.
func commitScript(cltvTime uint32, HKey,
	TKey *btcec.PublicKey, revokeHash [20]byte) ([]byte, error) {

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
	builder.AddInt64(int64(cltvTime))
	builder.AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
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

/*----- serialization for MultiOuts ------- */

/* Qchan serialization:
(it's just a utxo with their pubkey)
byte length   desc   at offset

53	utxo		0
33	thrpub	86

end len 	86

peeridx and multidx are inferred from position in db.
*/

func (m *Qchan) ToBytes() ([]byte, error) {
	var buf bytes.Buffer
	// first serialize the utxo part
	uBytes, err := m.Utxo.ToBytes()
	if err != nil {
		return nil, err
	}
	// write that into the buffer first
	_, err = buf.Write(uBytes)
	if err != nil {
		return nil, err
	}

	// write 33 byte pubkey (theirs)
	_, err = buf.Write(m.TheirPub.SerializeCompressed())
	if err != nil {
		return nil, err
	}
	// done
	return buf.Bytes(), nil
}

// MultiOutFromBytes turns bytes into a MultiOut.
// the first 53 bytes are the utxo, then next 33 is the pubkey
func QchanFromBytes(b []byte) (Qchan, error) {
	var m Qchan

	if len(b) < 86 {
		return m, fmt.Errorf("Got %d bytes for MultiOut, expect 86", len(b))
	}

	u, err := UtxoFromBytes(b[:53])
	if err != nil {
		return m, err
	}

	buf := bytes.NewBuffer(b[53:])
	// will be 33, size checked up there

	m.Utxo = u // assign the utxo

	m.TheirPub, err = btcec.ParsePubKey(buf.Bytes(), btcec.S256())
	if err != nil {
		return m, err
	}
	return m, nil
}
