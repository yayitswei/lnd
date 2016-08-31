package uspv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"sync"

	"github.com/boltdb/bolt"
	"github.com/lightningnetwork/lnd/lnutil"
	"github.com/lightningnetwork/lnd/portxo"
	"github.com/roasbeef/btcd/blockchain"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/btcutil/bloom"
	"github.com/roasbeef/btcutil/hdkeychain"
)

type TxStore struct {
	// could get rid of adr slice, it's just an in-ram cache...
	Adrs    []MyAdr  // endeavouring to acquire capital
	StateDB *bolt.DB // place to write all this down

	// Set of frozen utxos not to use... they point to the tx using em
	FreezeSet   map[wire.OutPoint]*FrozenTx
	FreezeMutex sync.Mutex

	// Params live here... AND SCon
	Param *chaincfg.Params // network parameters (testnet3, segnet, etc)

	// From here, comes everything. It's a secret to everybody.
	rootPrivKey *hdkeychain.ExtendedKey
}

type FrozenTx struct {
	Ins  []*portxo.PorTxo
	Outs []*wire.TxOut
	Txid wire.ShaHash
}

// Stxo is a utxo that has moved on.
type Stxo struct {
	portxo.PorTxo              // when it used to be a utxo
	SpendHeight   int32        // height at which it met its demise
	SpendTxid     wire.ShaHash // the tx that consumed it
}

type MyAdr struct { // an address I have the private key for
	PkhAdr btcutil.Address
	KeyIdx uint32 // index for private key needed to sign / spend
	// ^^ this is kindof redundant because it'll just be their position
	// inside the Adrs slice, right? leave for now
}

func NewTxStore(rootkey *hdkeychain.ExtendedKey, p *chaincfg.Params) TxStore {
	var txs TxStore
	txs.rootPrivKey = rootkey
	txs.Param = p
	txs.FreezeSet = make(map[wire.OutPoint]*FrozenTx)
	return txs
}

// add txid of interest
func (s *SPVCon) AddTxid(txid *wire.ShaHash, height int32) error {
	if txid == nil {
		return fmt.Errorf("tried to add nil txid")
	}
	log.Printf("added %s to OKTxids at height %d\n", txid.String(), height)
	s.OKMutex.Lock()
	s.OKTxids[*txid] = height
	s.OKMutex.Unlock()
	return nil
}

// add txid of interest
func (s *SPVCon) TxidExists(txid *wire.ShaHash) bool {
	if txid == nil {
		return false
	}
	s.OKMutex.Lock()
	_, ok := s.OKTxids[*txid]
	s.OKMutex.Unlock()
	return ok
}

// GimmeFilter ... or I'm gonna fade away
func (t *TxStore) GimmeFilter() (*bloom.Filter, error) {
	if len(t.Adrs) == 0 {
		return nil, fmt.Errorf("no address to filter for")
	}

	// get all utxos to add outpoints to filter
	allUtxos, err := t.GetAllUtxos()
	if err != nil {
		return nil, err
	}
	//	allQ, err := t.GetAllQchans()
	//	if err != nil {
	//		return nil, err
	//	}

	filterElements := uint32(len(allUtxos) + len(t.Adrs)) // + len(allQ))

	f := bloom.NewFilter(filterElements, 0, 0.0000001, wire.BloomUpdateAll)

	// note there could be false positives since we're just looking
	// for the 20 byte PKH without the opcodes.
	for _, a := range t.Adrs { // add 20-byte pubkeyhash
		f.Add(a.PkhAdr.ScriptAddress())
	}
	for _, u := range allUtxos {
		f.AddOutPoint(&u.Op)
	}
	// actually... we should monitor addresses, not txids, right?
	// or no...?
	//	for _, q := range allQ {
	// aha, add HASH here, not the outpoint! (txid of fund tx)
	//		f.AddShaHash(&q.Op.Hash)
	// also add outpoint...?  wouldn't the hash be enough?
	// not sure why I have to do both of these, but seems like close txs get
	// ignored without the outpoint, and fund txs get ignored without the
	// shahash. Might be that shahash operates differently (on txids, not txs)
	//		f.AddOutPoint(&q.Op)
	//	}
	// still some problem with filter?  When they broadcast a close which doesn't
	// send any to us, sometimes we don't see it and think the channel is still open.
	// so not monitoring the channel outpoint properly?  here or in ingest()

	fmt.Printf("made %d element filter\n", filterElements)
	return f, nil
}

// GetDoubleSpends takes a transaction and compares it with
// all transactions in the db.  It returns a slice of all txids in the db
// which are double spent by the received tx.
func CheckDoubleSpends(
	argTx *wire.MsgTx, txs []*wire.MsgTx) ([]*wire.ShaHash, error) {

	var dubs []*wire.ShaHash // slice of all double-spent txs
	argTxid := argTx.TxSha()

	for _, compTx := range txs {
		compTxid := compTx.TxSha()
		// check if entire tx is dup
		if argTxid.IsEqual(&compTxid) {
			return nil, fmt.Errorf("tx %s is dup", argTxid.String())
		}
		// not dup, iterate through inputs of argTx
		for _, argIn := range argTx.TxIn {
			// iterate through inputs of compTx
			for _, compIn := range compTx.TxIn {
				if lnutil.OutPointsEqual(
					argIn.PreviousOutPoint, compIn.PreviousOutPoint) {
					// found double spend
					dubs = append(dubs, &compTxid)
					break // back to argIn loop
				}
			}
		}
	}
	return dubs, nil
}

// TxToString prints out some info about a transaction. for testing / debugging
func TxToString(tx *wire.MsgTx) string {
	str := fmt.Sprintf("size %d vsize %d wsize %d locktime %d wit: %t txid %s\n",
		tx.SerializeSizeStripped(), blockchain.GetMsgTxVirtualSize(tx),
		tx.SerializeSize(), tx.LockTime, tx.HasWitness(), tx.TxSha().String())
	for i, in := range tx.TxIn {
		str += fmt.Sprintf("Input %d spends %s\n", i, in.PreviousOutPoint.String())
		str += fmt.Sprintf("\tSigScript: %x\n", in.SignatureScript)
		for j, wit := range in.Witness {
			str += fmt.Sprintf("\twitness %d: %x\n", j, wit)
		}
	}
	for i, out := range tx.TxOut {
		if out != nil {
			str += fmt.Sprintf("output %d script: %x amt: %d\n",
				i, out.PkScript, out.Value)
		} else {
			str += fmt.Sprintf("output %d nil (WARNING)\n", i)
		}
	}
	return str
}

/*----- serialization for stxos ------- */
/* Stxo serialization:
byte length   desc   at offset

53	utxo		0
4	sheight	53
32	stxid	57

end len 	89
*/

// ToBytes turns an Stxo into some bytes.
// prevUtxo serialization, then spendheight [4], spendtxid [32]
func (s *Stxo) ToBytes() ([]byte, error) {
	var buf bytes.Buffer

	// write 4 byte height where the txo was spent
	err := binary.Write(&buf, binary.BigEndian, s.SpendHeight)
	if err != nil {
		return nil, err
	}
	// write 32 byte txid of the spending transaction
	_, err = buf.Write(s.SpendTxid.Bytes())
	if err != nil {
		return nil, err
	}
	// first serialize the utxo part
	uBytes, err := s.PorTxo.Bytes()
	if err != nil {
		return nil, err
	}
	// write that into the buffer first
	_, err = buf.Write(uBytes)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// StxoFromBytes turns bytes into a Stxo.
// first 36 bytes are how it's spent, after that is portxo
func StxoFromBytes(b []byte) (Stxo, error) {
	var s Stxo
	if len(b) < 96 {
		return s, fmt.Errorf("Got %d bytes for stxo, expect 89", len(b))
	}
	buf := bytes.NewBuffer(b)
	// read 4 byte spend height
	err := binary.Read(buf, binary.BigEndian, &s.SpendHeight)
	if err != nil {
		return s, err
	}
	// read 32 byte txid
	err = s.SpendTxid.SetBytes(buf.Next(32))
	if err != nil {
		return s, err
	}

	u, err := portxo.PorTxoFromBytes(buf.Bytes())
	if err != nil {
		return s, err
	}
	s.PorTxo = *u // assign the utxo

	return s, nil
}
