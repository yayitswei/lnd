package uspv

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/boltdb/bolt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
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
	KEYElkRecv = []byte("ElkR") // indicates elkrem receiver
	KEYIdx     = []byte("idx")  // indicates elkrem receiver
	KEYutxo    = []byte("utx")  // indicates channel remote pubkey
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

// GetPubkeyBytes generates and returns the pubkey for a given index.
// It will return nil if there's an error / problem
func (ts *TxStore) GetPubkeyBytes(peerIdx, cIdx uint32) []byte {
	multiRoot, err := ts.rootPrivKey.Child(2 + hdkeychain.HardenedKeyStart)
	if err != nil {
		fmt.Printf("GetPubkeyBytes err %s", err.Error())
		return nil
	}
	peerRoot, err := multiRoot.Child(peerIdx + hdkeychain.HardenedKeyStart)
	if err != nil {
		fmt.Printf("GetPubkeyBytes err %s", err.Error())
		return nil
	}
	multiPriv, err := peerRoot.Child(cIdx + hdkeychain.HardenedKeyStart)
	if err != nil {
		fmt.Printf("GetPubkeyBytes err %s", err.Error())
		return nil
	}
	pub, err := multiPriv.ECPubKey()
	if err != nil {
		fmt.Printf("GetPubkeyBytes err %s", err.Error())
		return nil
	}
	return pub.SerializeCompressed()
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
			return fmt.Errorf("No peers evar")
		}
		pr := prs.Bucket(pub.SerializeCompressed())
		if pr == nil {
			return fmt.Errorf("Peer %x has no index saved",
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
			return fmt.Errorf("no peers")
		}
		pr := prs.Bucket(peerBytes)
		if pr == nil {
			return fmt.Errorf("peer %x not found", peerBytes)
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
			return fmt.Errorf("no peers")
		}
		pr := prs.Bucket(peerBytes)
		if pr == nil {
			return fmt.Errorf("peer %x not found", peerBytes)
		}
		peerIdxBytes := pr.Get(KEYIdx)
		if peerIdxBytes == nil {
			return fmt.Errorf("peer %x has no index? db bad", peerBytes)
		}
		peerIdx = BtU32(peerIdxBytes) // store for key creation
		multIdx = uint32(pr.Stats().KeyN)
		return nil
	})
	if err != nil {
		return nil, err
	}

	pubBytes := ts.GetPubkeyBytes(peerIdx, multIdx)
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
func (ts *TxStore) MakeMultiTx(tx *wire.MsgTx, amt int64, peerBytes []byte,
	theirPub *btcec.PublicKey) (*wire.OutPoint, []byte, error) {

	var peerIdx, multIdx uint32
	var op *wire.OutPoint
	var myPubBytes []byte

	theirPubBytes := theirPub.SerializeCompressed()
	err := ts.StateDB.Update(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers) // go into bucket for all peers
		if prs == nil {
			return fmt.Errorf("no peers")
		}
		pr := prs.Bucket(peerBytes) // go into this peers bucket
		if pr == nil {
			return fmt.Errorf("peer %x not found", peerBytes)
		}
		peerIdxBytes := pr.Get(KEYIdx) // find peer index
		if peerIdxBytes == nil {
			return fmt.Errorf("peer %x has no index? db bad", peerBytes)
		}
		peerIdx = BtU32(peerIdxBytes) // store peer index for key creation
		multIdx = uint32(pr.Stats().BucketN) + localIdx

		// generate pubkey from peer, multi indexes
		myPubBytes = ts.GetPubkeyBytes(peerIdx, multIdx)

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

		// save multiout in the bucket
		err = multiBucket.Put(KEYutxo, mOutBytes)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return op, myPubBytes, nil
}

// SaveMultiTx saves the data in a multiDesc to DB.  We know the outpoint
// but that's about it.  Do detection, verification, and capacity check
// once the outpoint is seen on 8333.
func (ts *TxStore) SaveMultiTx(op *wire.OutPoint, amt int64,
	peerBytes []byte, theirPub *btcec.PublicKey) error {

	var multIdx uint32

	return ts.StateDB.Update(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers) // go into bucket for all peers
		if prs == nil {
			return fmt.Errorf("no peers")
		}
		pr := prs.Bucket(peerBytes) // go into this peers bucket
		if pr == nil {
			return fmt.Errorf("peer %x not found", peerBytes)
		}
		peerIdxBytes := pr.Get(KEYIdx) // find peer index
		if peerIdxBytes == nil {
			return fmt.Errorf("peer %x has no index? db bad", peerBytes)
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
