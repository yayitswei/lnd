package uspv

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/boltdb/bolt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcutil/txsort"
)

/*
Channels (& multisig) go in the DB here.
first there's the peer bucket.

Here's the structure:

Peers
|
|-Pubkey
	|
	|-idx:uint32 - assign a 32bit number to this peer for HD keys and quick ref
	|
	|-channelID (36 byte outpoint)
		|
		|-idx: uint32 - assign a 32 bit number for each channel w/ peer
		|
		|-channel state data


Right now these buckets are all in one boltDB.  This limits it to one db write
at a time, which for super high thoughput could be too slow.
Later on we can chop it up so that each channel gets it's own db file.

*/
const (
	// when pubkeys are made for a locally funded channel, add / and this
	localIdx = 1 << 30
)

var (
	BKTPeers   = []byte("Peer") // all peer data is in this bucket.
	KEYElkRecv = []byte("ElkR") // elkrem receiver
	KEYIdx     = []byte("idx")  // index for key derivation
	KEYutxo    = []byte("utx")  // serialized mutxo / cutxo
	KEYUnsig   = []byte("usig") // unsigned fund tx
	KEYCladr   = []byte("cdr")  // close address (Don't make fun of my lisp)
)

// I shouldn't even have to write these...

// uint32 to 4 bytes.  Always works.
func U32tB(i uint32) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, i)
	return buf.Bytes()
}

// 4 byte slice to uin32.  Returns ffffffff if something doesn't work.
func BtU32(b []byte) uint32 {
	if len(b) != 4 {
		fmt.Printf("Got %x to BtU32\n", b)
		return 0xffffffff
	}
	var i uint32
	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.BigEndian, &i)
	return i
}

// int64 to 8 bytes.  Always works.
func I64tB(i int64) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, i)
	return buf.Bytes()
}

// 8 bytes to int64 (bitcoin amounts).  returns 8x ff if it doesn't work.
func BtI64(b []byte) int64 {
	if len(b) != 8 {
		fmt.Printf("Got %x to BtI64\n", b)
		return -0x7fffffffffffffff
	}
	var i int64
	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.BigEndian, &i)
	return i
}

// GetFundPrivkey generates and returns the private key for a given index.
// It will return nil if there's an error / problem, but there shouldn't be
// unless the root key itself isn't there or something.
func (ts *TxStore) GetFundPrivkey(peerIdx, cIdx uint32) *btcec.PrivateKey {
	fmt.Printf("\tgenerating key for peerindex %d, keyindex %d\n", peerIdx, cIdx)

	multiRoot, err := ts.rootPrivKey.Child(2 + hdkeychain.HardenedKeyStart)
	if err != nil {
		fmt.Printf("GetFundPrivkey err %s", err.Error())
		return nil
	}
	peerRoot, err := multiRoot.Child(peerIdx + hdkeychain.HardenedKeyStart)
	if err != nil {
		fmt.Printf("GetFundPrivkey err %s", err.Error())
		return nil
	}
	multiChild, err := peerRoot.Child(cIdx + hdkeychain.HardenedKeyStart)
	if err != nil {
		fmt.Printf("GetFundPrivkey err %s", err.Error())
		return nil
	}
	priv, err := multiChild.ECPrivKey()
	if err != nil {
		fmt.Printf("GetFundPrivkey err %s", err.Error())
		return nil
	}
	fmt.Printf("-----generated %x\n", priv.PubKey().SerializeCompressed())
	return priv
}

// GetFundPubkeyBytes generates and returns the pubkey for a given index.
// It will return nil if there's an error / problem
func (ts *TxStore) GetFundPubkeyBytes(peerIdx, cIdx uint32) []byte {
	priv := ts.GetFundPrivkey(peerIdx, cIdx)
	if priv == nil {
		fmt.Printf("GetFundPubkeyBytes peer %d idx %d failed", peerIdx, cIdx)
		return nil
	}
	return priv.PubKey().SerializeCompressed()
}

// NewPeer saves a pubkey in the DB and assigns a peer index.  Call this
// the first time you connect to someone.  Returns false if already known,
// true if it added a new peer.  Errors for real errors.
func (ts *TxStore) NewPeer(pub *btcec.PublicKey) (bool, error) {
	itsnew := true
	err := ts.StateDB.Update(func(btx *bolt.Tx) error {
		prs, _ := btx.CreateBucketIfNotExists(BKTPeers) // only errs on name

		newPeerIdx := uint32(prs.Stats().KeyN) + 1 // new peer index.
		// starts at 1. There IS NO PEER 0, so you can consider peer 0 invalid.

		pr, err := prs.CreateBucket(pub.SerializeCompressed())
		if err != nil {
			itsnew = false
			return nil // peer already exists
		}

		var buf bytes.Buffer
		// write 4 byte peer index
		err = binary.Write(&buf, binary.BigEndian, newPeerIdx)
		if err != nil {
			return err
		}
		return pr.Put(KEYIdx, buf.Bytes())
	})
	return itsnew, err
}

// GetPeerIdx returns the peer index given a pubkey.
func (ts *TxStore) GetPeerIdx(pub *btcec.PublicKey) (uint32, error) {
	var idx uint32
	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers)
		if prs == nil {
			return fmt.Errorf("GetPeerIdx: No peers evar")
		}
		pr := prs.Bucket(pub.SerializeCompressed())
		if pr == nil {
			return fmt.Errorf("GetPeerIdx: Peer %x has no index saved",
				pub.SerializeCompressed())
		}
		idx = BtU32(pr.Get(KEYIdx))
		return nil
	})
	return idx, err
}

// Initiate a Multisig Request.  Get an index based on peer pubkey
func (ts *TxStore) NewMultReq(peerBytes []byte) (uint32, error) {
	var multIdx uint32
	err := ts.StateDB.Update(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers)
		if prs == nil {
			return fmt.Errorf("NewMultReq: no peers")
		}
		pr := prs.Bucket(peerBytes)
		if pr == nil {
			return fmt.Errorf("NewMultReq: peer %x not found", peerBytes)
		}
		// chanIdx starts at 1, because there's another key in the peer bucket
		// (pdx) for peer data (right now just peerIdx)
		multIdx = uint32(pr.Stats().KeyN)
		// make empty bucket for the new multisig
		_, err := pr.CreateBucket(U32tB(multIdx))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	return multIdx, nil
}

// NextPubForPeer returns the next pubkey to use with the peer.
// It first checks that the peer exists, next pubkey.  Read only.
func (ts *TxStore) NextPubForPeer(peerBytes []byte) ([]byte, error) {
	var peerIdx, multIdx uint32
	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers)
		if prs == nil {
			return fmt.Errorf("NextPubForPeer: no peers")
		}
		pr := prs.Bucket(peerBytes)
		if pr == nil {
			return fmt.Errorf("NextPubForPeer: peer %x not found", peerBytes)
		}
		peerIdxBytes := pr.Get(KEYIdx)
		if peerIdxBytes == nil {
			return fmt.Errorf("NextPubForPeer: peer %x has no index? db bad", peerBytes)
		}
		peerIdx = BtU32(peerIdxBytes) // store for key creation
		multIdx = uint32(pr.Stats().KeyN)
		return nil
	})
	if err != nil {
		return nil, err
	}

	pubBytes := ts.GetFundPubkeyBytes(peerIdx, multIdx)
	return pubBytes, nil
}

// MakeMultiTx fills out a multisig funding tx.
// You need to give it a partial tx with the inputs and change output
// (everything but the multisig output), the amout of the multisig output,
// the peerID, and the peer's multisig pubkey.
// It then creates the local multisig pubkey, makes the output, and stores
// the multi tx info in the db.  Doesn't RETURN a tx, but the *tx you
// hand it will be filled in.  (but not signed!)
// Returns the multi outpoint and myPubkey (bytes) & err
// also... this is kindof ugly.  It could be re-written as a more integrated func
// which figures out the inputs and outputs.  So basically move
// most of the code from MultiRespHandler() into here.  Yah.. should do that.
//TODO ^^^^^^^^^^
func (ts *TxStore) MakeFundTx(tx *wire.MsgTx, amt int64, peerBytes []byte,
	theirPub *btcec.PublicKey) (*wire.OutPoint, []byte, error) {

	var peerIdx, multIdx uint32
	var op *wire.OutPoint
	var myPubBytes []byte

	theirPubBytes := theirPub.SerializeCompressed()
	err := ts.StateDB.Update(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers) // go into bucket for all peers
		if prs == nil {
			return fmt.Errorf("MakeMultiTx: no peers")
		}
		pr := prs.Bucket(peerBytes) // go into this peers bucket
		if pr == nil {
			return fmt.Errorf("MakeMultiTx: peer %x not found", peerBytes)
		}
		peerIdxBytes := pr.Get(KEYIdx) // find peer index
		if peerIdxBytes == nil {
			return fmt.Errorf("MakeMultiTx: peer %x has no index? db bad", peerBytes)
		}
		peerIdx = BtU32(peerIdxBytes)                   // store peer index for key creation
		multIdx = uint32(pr.Stats().BucketN) + localIdx // local so high bit 1

		// generate pubkey from peer, multi indexes
		myPubBytes = ts.GetFundPubkeyBytes(peerIdx, multIdx)

		// generate multisig output from two pubkeys
		multiTxOut, err := FundMultiOut(theirPubBytes, myPubBytes, amt)
		if err != nil {
			return err
		}
		// stash script for post-sort detection (kindof ugly)
		outScript := multiTxOut.PkScript
		tx.AddTxOut(multiTxOut) // add mutlisig output to tx

		// figure out outpoint of new multiacct
		txsort.InPlaceSort(tx) // sort before getting outpoint
		txid := tx.TxSha()     // got the txid

		// find index... it will actually be 1 or 0 but do this anyway
		for i, out := range tx.TxOut {
			if bytes.Equal(out.PkScript, outScript) {
				op = wire.NewOutPoint(&txid, uint32(i))
				break // found it
			}
		}
		// make new bucket for this mutliout
		multiBucket, err := pr.CreateBucket(OutPointToBytes(*op))
		if err != nil {
			return err
		}

		var mUtxo Utxo      // create new utxo and copy into it
		mUtxo.AtHeight = -1 // not even broadcast yet
		mUtxo.KeyIdx = multIdx
		mUtxo.Value = amt
		mUtxo.IsWit = true // multi/chan always wit
		mUtxo.Op = *op
		var mOut MultiOut
		mOut.Utxo = mUtxo
		mOut.TheirPub = theirPub
		// serialize multiOut
		mOutBytes, err := mOut.ToBytes()
		if err != nil {
			return err
		}

		// save multioutpoint in the bucket
		err = multiBucket.Put(KEYutxo, mOutBytes)
		if err != nil {
			return err
		}
		// stash whole TX in unsigned bucket
		// you don't need to remember which key goes to which txin
		// since the outpoint is right there and quick to look up.

		//TODO -- Problem!  These utxos are not flagged or removed until
		// the TX is signed and sent.  If other txs happen before the
		// ack comes in, the signing could fail.  So... call utxos
		// spent here I guess.

		var buf bytes.Buffer
		tx.SerializeWitness(&buf) // no witness yet, but it will be witty
		return multiBucket.Put(KEYUnsig, buf.Bytes())
	})
	if err != nil {
		return nil, nil, err
	}

	return op, myPubBytes, nil
}

// SaveMultiTx saves the data in a multiDesc to DB.  We know the outpoint
// but that's about it.  Do detection, verification, and capacity check
// once the outpoint is seen on 8333.
func (ts *TxStore) SaveFundTx(op *wire.OutPoint, amt int64,
	peerBytes []byte, theirPub *btcec.PublicKey) error {

	var multIdx uint32

	return ts.StateDB.Update(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers) // go into bucket for all peers
		if prs == nil {
			return fmt.Errorf("SaveMultiTx: no peers")
		}
		pr := prs.Bucket(peerBytes) // go into this peers bucket
		if pr == nil {
			return fmt.Errorf("SaveMultiTx: peer %x not found", peerBytes)
		}
		// just sanity checking here, not used
		peerIdxBytes := pr.Get(KEYIdx) // find peer index
		if peerIdxBytes == nil {
			return fmt.Errorf("SaveMultiTx: peer %x has no index? db bad", peerBytes)
		}
		multIdx = uint32(pr.Stats().BucketN) // new non local, high bit 0

		// make new bucket for this mutliout
		multiBucket, err := pr.CreateBucket(OutPointToBytes(*op))
		if err != nil {
			return err
		}

		var mUtxo Utxo      // create new utxo and copy into it
		mUtxo.AtHeight = -1 // not even broadcast yet
		mUtxo.KeyIdx = multIdx
		mUtxo.Value = amt
		mUtxo.IsWit = true // multi/chan always wit
		mUtxo.Op = *op
		var mOut MultiOut
		mOut.Utxo = mUtxo
		mOut.TheirPub = theirPub
		// serialize multiOut
		mOutBytes, err := mOut.ToBytes()
		if err != nil {
			return err
		}

		// save multiout in the bucket
		err = multiBucket.Put(KEYutxo, mOutBytes)
		if err != nil {
			return err
		}
		return nil
	})
}

// SignMultiTx happens once everything's ready for the tx to be signed and
// broadcast (once you get it ack'd.  It finds the mutli tx, signs it and
// returns it.  Presumably you send this tx out to the network once it's returned.
// this function itself doesn't modify height, so it'll still be at -1 untill
// Ingest() makes it 0 or an acutal block height.
func (ts *TxStore) SignFundTx(
	op *wire.OutPoint, peerBytes []byte) (*wire.MsgTx, error) {

	tx := wire.NewMsgTx()

	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		duf := btx.Bucket(BKTUtxos)
		if duf == nil {
			return fmt.Errorf("SignMultiTx: no duffel bag")
		}

		prs := btx.Bucket(BKTPeers)
		if prs == nil {
			return fmt.Errorf("SignMultiTx: no peers")
		}
		pr := prs.Bucket(peerBytes) // go into this peers bucket
		if pr == nil {
			return fmt.Errorf("SignMultiTx: peer %x not found", peerBytes)
		}
		// just sanity checking here, not used
		peerIdxBytes := pr.Get(KEYIdx) // find peer index
		if peerIdxBytes == nil {
			return fmt.Errorf("SignMultiTx: peer %x has no index? db bad", peerBytes)
		}
		opBytes := OutPointToBytes(*op)
		multiBucket := pr.Bucket(opBytes)
		if multiBucket == nil {
			return fmt.Errorf("SignMultiTx: outpoint %s not in db", op.String())
		}
		txBytes := multiBucket.Get(KEYUnsig)

		buf := bytes.NewBuffer(txBytes)
		err := tx.Deserialize(buf)
		if err != nil {
			return err
		}
		hCache := txscript.CalcHashCache(tx, 0, txscript.SigHashAll)
		// got tx, now figure out keys for the inputs and sign.
		for i, txin := range tx.TxIn {
			halfUtxo := duf.Get(OutPointToBytes(txin.PreviousOutPoint))
			if halfUtxo == nil {
				return fmt.Errorf("SignMultiTx: input %d not in utxo set", i)
			}

			// key index is 4 bytes in to the val (36 byte outpoint is key)
			kIdx := BtU32(halfUtxo[4:8])
			// amt is 8 bytes in
			amt := BtI64(halfUtxo[8:16])

			child, err := ts.rootPrivKey.Child(kIdx + hdkeychain.HardenedKeyStart)
			if err != nil {
				return err
			}
			priv, err := child.ECPrivKey()
			if err != nil {
				return err
			}
			// gotta add subscripts to sign
			witAdr, err := btcutil.NewAddressWitnessPubKeyHash(
				ts.Adrs[kIdx].PkhAdr.ScriptAddress(), ts.Param)
			if err != nil {
				return err
			}
			subScript, err := txscript.PayToAddrScript(witAdr)
			if err != nil {
				return err
			}
			tx.TxIn[i].Witness, err = txscript.WitnessScript(
				tx, hCache, i, amt, subScript,
				txscript.SigHashAll, priv, true)
			if err != nil {
				return err
			}
			// witness added OK
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return tx, nil
}

//wa, err := btcutil.NewAddressWitnessPubKeyHash(
//			SCon.TS.Adrs[utxo.KeyIdx].PkhAdr.ScriptAddress(), SCon.TS.Param)
//		prevPKScript, err := txscript.PayToAddrScript(wa)
//		if err != nil {
//			fmt.Printf("MultiRespHandler err %s", err.Error())
//			return
//		}

// GetAllMultiOuts returns a slice of all Multiouts. empty slice is OK.
func (ts *TxStore) GetAllMultiOuts() ([]*MultiOut, error) {
	var multis []*MultiOut
	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers)
		if prs == nil {
			return nil
		}
		return prs.ForEach(func(idPub, nothin []byte) error {
			if nothin != nil {
				return nil // non-bucket
			}

			pr := prs.Bucket(idPub) // go into this peer's bucket
			peerIdx := BtU32(pr.Get(KEYIdx))

			return pr.ForEach(func(op, nthin []byte) error {
				//				fmt.Printf("key %x ", op)
				if nthin != nil {
					//					fmt.Printf("val %x\n", nthin)
					return nil // non-bucket / outpoint
				}
				multBkt := pr.Bucket(op)
				if multBkt == nil {
					return nil // nothing stored
				}
				newMult, err := MultiOutFromBytes(multBkt.Get(KEYutxo))
				if err != nil {
					return err
				}

				newMult.PeerIdx = peerIdx
				multis = append(multis, &newMult)
				return nil
			})
			return nil
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return multis, nil
}

// GetMultiOut returns a single multi out.  You need to specify the peer
// pubkey and outpoint bytes.
func (ts *TxStore) GetMultiOut(
	peerBytes []byte, opArr [36]byte) (*MultiOut, error) {

	var multi MultiOut
	var err error
	op := OutPointFromBytes(opArr)
	err = ts.StateDB.View(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers)
		if prs == nil {
			return fmt.Errorf("no peers")
		}
		pr := prs.Bucket(peerBytes[:]) // go into this peer's bucket
		if pr == nil {
			return fmt.Errorf("peer %x not in db", peerBytes)
		}
		multiBucket := pr.Bucket(opArr[:])
		if multiBucket == nil {
			return fmt.Errorf("outpoint %s not in db under peer %x",
				op.String(), peerBytes)
		}

		multi, err = MultiOutFromBytes(multiBucket.Get(KEYutxo))
		if err != nil {
			return err
		}
		// note that peerIndex is not set from deserialization!  set it here!
		multi.PeerIdx = BtU32(pr.Get(KEYIdx))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &multi, nil
}

// SetMultiClose sets the address to close to.
func (ts *TxStore) SetMultiClose(
	peerBytes []byte, opArr [36]byte, adrArr [20]byte) error {

	return ts.StateDB.Update(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers)
		if prs == nil {
			return fmt.Errorf("no peers")
		}
		pr := prs.Bucket(peerBytes[:]) // go into this peer's bucket
		if pr == nil {
			return fmt.Errorf("peer %x not in db", peerBytes)
		}
		multiBucket := pr.Bucket(opArr[:])
		if multiBucket == nil {
			return fmt.Errorf("outpoint (reversed) %x not in db under peer %x",
				opArr, peerBytes)
		}
		err := multiBucket.Put(KEYCladr, adrArr[:])
		if err != nil {
			return err
		}
		return nil
	})
}

// GetMultiClose recalls the address the multisig/channel has been requested to
// close to.  If there's nothing there it returns a nil slice and an error.
func (ts *TxStore) GetMultiClose(peerBytes []byte, opArr [36]byte) ([]byte, error) {
	adrBytes := make([]byte, 20)

	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers)
		if prs == nil {
			return fmt.Errorf("no peers")
		}
		pr := prs.Bucket(peerBytes[:]) // go into this peer's bucket
		if pr == nil {
			return fmt.Errorf("peer %x not in db", peerBytes)
		}
		multiBucket := pr.Bucket(opArr[:])
		if multiBucket == nil {
			return fmt.Errorf("outpoint (reversed) %x not in db under peer %x",
				opArr, peerBytes)
		}
		adrToxicBytes := multiBucket.Get(KEYCladr)
		if adrToxicBytes == nil {
			return fmt.Errorf("%x in peer %x has no close address",
				opArr, peerBytes)
		}
		copy(adrBytes, adrToxicBytes)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return adrBytes, nil
}

/*----- serialization for MultiOuts ------- */

/* MultiOuts serialization:
(it's just a utxo with their pubkey)
byte length   desc   at offset

53	utxo		0
33	thrpub	86

end len 	86

peeridx and multidx are inferred from position in db.
*/

func (m *MultiOut) ToBytes() ([]byte, error) {
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
func MultiOutFromBytes(b []byte) (MultiOut, error) {
	var m MultiOut

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
