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

// CountKeysInBucket is needed for NewPeer.  Counts keys in a bucket without
// going into the sub-buckets and their keys. 2^32 max.
// returns 0xffffffff if there's an error
func CountKeysInBucket(bkt *bolt.Bucket) uint32 {
	var i uint32
	err := bkt.ForEach(func(_, _ []byte) error {
		i++
		return nil
	})
	if err != nil {
		fmt.Printf("CountKeysInBucket error: %s\n", err.Error())
		return 0xffffffff
	}
	return i
}

// NewPeer saves a pubkey in the DB and assigns a peer index.  Call this
// the first time you connect to someone.  Returns false if already known,
// true if it added a new peer.  Errors for real errors.
func (ts *TxStore) NewPeer(pub *btcec.PublicKey) (bool, error) {
	itsnew := true
	err := ts.StateDB.Update(func(btx *bolt.Tx) error {
		prs, _ := btx.CreateBucketIfNotExists(BKTPeers) // only errs on name

		// you can't use KeyN because that includes everything in sub-buckets.
		// so we have to count the number of peers here.
		// If it's slow we could cache it but you probably won't have
		// millions of peers.

		newPeerIdx := CountKeysInBucket(prs) + 1
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

// NewFundReq initiate a channel request.  Get an index based on peer pubkey
func (ts *TxStore) NewFundReq(peerBytes []byte) (uint32, error) {
	var cIdx uint32
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
		cIdx = uint32(pr.Stats().BucketN)
		// make empty bucket for the new multisig
		_, err := pr.CreateBucket(U32tB(cIdx))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	return cIdx, nil
}

// NextPubForPeer returns the next pubkey to use with the peer.
// It first checks that the peer exists, next pubkey.  Read only.
func (ts *TxStore) NextPubForPeer(peerBytes []byte) ([]byte, []byte, error) {
	var peerIdx, cIdx uint32
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
		// can't use keyN.  Use BucketN.  So we start at 1.  Also this means
		// NO SUB-BUCKETS in peers.  If we want to add sub buckets we'll need
		// to count or track a different way.
		// nah we can't use this.  Gotta count each time.  Lame.
		cIdx = uint32(pr.Stats().BucketN)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	pub := ts.GetFundPubkey(peerIdx, cIdx)
	adr := ts.GetRefundAddressBytes(peerIdx, cIdx)
	if pub == nil || adr == nil {
		return nil, nil, fmt.Errorf("NextPubForPeer: nil key")
	}
	return pub.SerializeCompressed(), adr, nil
}

// MakeFundTx fills out a channel funding tx.
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
func (ts *TxStore) MakeFundTx(
	tx *wire.MsgTx, amt int64, peerBytes []byte, theirPub *btcec.PublicKey,
	theirRefund [20]byte) (*wire.OutPoint, []byte, []byte, error) {

	var peerIdx, cIdx uint32
	var op *wire.OutPoint
	var myPubBytes, myRefundBytes []byte
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
		peerIdx = BtU32(peerIdxBytes)                // store peer index for key creation
		cIdx = uint32(pr.Stats().BucketN) + localIdx // local so high bit 1

		// generate pubkey from peer, multi indexes
		myPub := ts.GetFundPubkey(peerIdx, cIdx)
		myRefundBytes := ts.GetRefundAddressBytes(peerIdx, cIdx)
		if myPub == nil || myRefundBytes == nil {
			return fmt.Errorf("nil key")
		}
		myPubBytes = myPub.SerializeCompressed()
		// generate multisig output from two pubkeys
		multiTxOut, err := FundTxOut(theirPubBytes, myPubBytes, amt)
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
		mUtxo.KeyIdx = cIdx
		mUtxo.Value = amt
		mUtxo.IsWit = true // multi/chan always wit
		mUtxo.Op = *op
		var qc Qchan
		qc.Utxo = mUtxo
		qc.TheirPub = theirPub
		qc.TheirRefundAdr = theirRefund
		// serialize multiOut
		mOutBytes, err := qc.ToBytes()
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
		return nil, nil, nil, err
	}

	return op, myPubBytes, myRefundBytes, nil
}

// SaveFundTx saves the data in a multiDesc to DB.  We know the outpoint
// but that's about it.  Do detection, verification, and capacity check
// once the outpoint is seen on 8333.
func (ts *TxStore) SaveFundTx(op *wire.OutPoint, amt int64,
	peerBytes []byte, theirPub *btcec.PublicKey, theirRefund [20]byte) error {

	var cIdx uint32

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
		cIdx = uint32(pr.Stats().BucketN) // new non local, high bit 0

		// make new bucket for this mutliout
		multiBucket, err := pr.CreateBucket(OutPointToBytes(*op))
		if err != nil {
			return err
		}

		var mUtxo Utxo      // create new utxo and copy into it
		mUtxo.AtHeight = -1 // not even broadcast yet
		mUtxo.KeyIdx = cIdx
		mUtxo.Value = amt
		mUtxo.IsWit = true // multi/chan always wit
		mUtxo.Op = *op
		var qc Qchan
		qc.Utxo = mUtxo
		qc.TheirPub = theirPub
		qc.TheirRefundAdr = theirRefund
		// serialize multiOut
		mOutBytes, err := qc.ToBytes()
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

// SignFundTx happens once everything's ready for the tx to be signed and
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

		hCache := txscript.NewTxSigHashes(tx)
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

			priv := ts.GetWalletPrivkey(kIdx)

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

// GetAllQchans returns a slice of all Multiouts. empty slice is OK.
func (ts *TxStore) GetAllQchans() ([]*Qchan, error) {
	var qChans []*Qchan
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
				qcBucket := pr.Bucket(op)
				if qcBucket == nil {
					return nil // nothing stored
				}
				newQc, err := QchanFromBytes(qcBucket.Get(KEYutxo))
				if err != nil {
					return err
				}
				// fill in peerIdx from db context
				newQc.PeerIdx = peerIdx
				// fill in myPub from index
				newQc.MyPub = ts.GetFundPubkey(peerIdx, newQc.KeyIdx)
				// fill in my refund from index
				copy(newQc.MyRefundAdr[:],
					ts.GetRefundAddressBytes(peerIdx, newQc.KeyIdx))
				// add to slice
				qChans = append(qChans, &newQc)
				return nil
			})
			return nil
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return qChans, nil
}

// GetQchan returns a single multi out.  You need to specify the peer
// pubkey and outpoint bytes.
func (ts *TxStore) GetQchan(
	peerBytes []byte, opArr [36]byte) (*Qchan, error) {

	var qc Qchan
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
		qcBucket := pr.Bucket(opArr[:])
		if qcBucket == nil {
			return fmt.Errorf("outpoint %s not in db under peer %x",
				op.String(), peerBytes)
		}

		qc, err = QchanFromBytes(qcBucket.Get(KEYutxo))
		if err != nil {
			return err
		}
		// note that peerIndex is not set from deserialization!  set it here!
		qc.PeerIdx = BtU32(pr.Get(KEYIdx))

		qc.MyPub = ts.GetFundPubkey(qc.PeerIdx, qc.KeyIdx)
		// fill in my refund from index
		copy(qc.MyRefundAdr[:], ts.GetRefundAddressBytes(qc.PeerIdx, qc.KeyIdx))

		// fill in myPub from index
		//		multi.MyPub = ts.GetFundPubkey(multi.PeerIdx, multi.KeyIdx)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &qc, nil
}

// GetQchanByIdx is a gets the channel when you don't know the peer bytes and
// outpoint.  Probably shouldn't have to use this if the UI is done right though.
func (ts *TxStore) GetQchanByIdx(peerIdx, cIdx uint32) (*Qchan, error) {
	var qc *Qchan
	var err error
	err = ts.StateDB.View(func(btx *bolt.Tx) error {
		prs := btx.Bucket(BKTPeers)
		if prs == nil {
			return fmt.Errorf("no peers")
		}
		// look through peers for peer index
		prs.ForEach(func(idPub, nothin []byte) error {
			if nothin != nil {
				return nil // non-bucket
			}
			if qc != nil {
				return nil
			}
			pr := prs.Bucket(idPub) // go into this peer's bucket
			if BtU32(pr.Get(KEYIdx)) == peerIdx {
				return pr.ForEach(func(op, nthin []byte) error {
					if nthin != nil {
						return nil // non-bucket / outpoint
					}
					if qc != nil {
						return nil
					}
					qcBkt := pr.Bucket(op)
					if qcBkt == nil {
						return nil // nothing stored
					}
					newQc, err := QchanFromBytes(qcBkt.Get(KEYutxo))
					if err != nil {
						return err
					}
					if newQc.KeyIdx == cIdx {
						// fill in peerIdx from db context
						newQc.PeerIdx = peerIdx
						qc = &newQc
					}
					return nil
				})
			}
			return nil
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if qc == nil {
		return nil, fmt.Errorf("channel (%d,%d) not found in db", peerIdx, cIdx)
	}
	return qc, nil
}

// SetChanClose sets the address to close to.
func (ts *TxStore) SetChanClose(
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

// GetChanClose recalls the address the multisig/channel has been requested to
// close to.  If there's nothing there it returns a nil slice and an error.
func (ts *TxStore) GetChanClose(peerBytes []byte, opArr [36]byte) ([]byte, error) {
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
