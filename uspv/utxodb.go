package uspv

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/roasbeef/btcd/blockchain"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"

	"github.com/boltdb/bolt"
)

var (
	BKTUtxos = []byte("DuffelBag") // leave the rest to collect interest
	BKTStxos = []byte("SpentTxs")  // for bookkeeping
	BKTTxns  = []byte("Txns")      // all txs we care about, for replays
	BKTState = []byte("MiscState") // last state of DB
	// these are in the state bucket
	KEYNumKeys   = []byte("NumKeys")   // number of p2pkh keys used
	KEYNumMulti  = []byte("NumMulti")  // number of p2pkh keys used
	KEYTipHeight = []byte("TipHeight") // height synced to
)

func (ts *TxStore) OpenDB(filename string) error {
	var err error
	var numKeys uint32
	ts.StateDB, err = bolt.Open(filename, 0644, nil)
	if err != nil {
		return err
	}
	// create buckets if they're not already there
	err = ts.StateDB.Update(func(btx *bolt.Tx) error {
		_, err = btx.CreateBucketIfNotExists(BKTUtxos)
		if err != nil {
			return err
		}
		_, err = btx.CreateBucketIfNotExists(BKTStxos)
		if err != nil {
			return err
		}
		_, err = btx.CreateBucketIfNotExists(BKTTxns)
		if err != nil {
			return err
		}
		sta, err := btx.CreateBucketIfNotExists(BKTState)
		if err != nil {
			return err
		}

		numKeysBytes := sta.Get(KEYNumKeys)
		if numKeysBytes != nil { // NumKeys exists, read into uint32
			buf := bytes.NewBuffer(numKeysBytes)
			err := binary.Read(buf, binary.BigEndian, &numKeys)
			if err != nil {
				return err
			}
			fmt.Printf("db says %d keys\n", numKeys)
		} else { // no adrs yet, make it 1 (why...?)
			numKeys = 1
			var buf bytes.Buffer
			err = binary.Write(&buf, binary.BigEndian, numKeys)
			if err != nil {
				return err
			}
			err = sta.Put(KEYNumKeys, buf.Bytes())
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return ts.PopulateAdrs(numKeys)
}

// make a new change output.  I guess this is supposed to be on a different
// branch than regular addresses...
func (ts *TxStore) NewChangeOut(amt int64) (*wire.TxOut, error) {
	changeOld, err := ts.NewAdr() // change is always witnessy
	if err != nil {
		return nil, err
	}
	changeAdr, err := btcutil.NewAddressWitnessPubKeyHash(
		changeOld.ScriptAddress(), ts.Param)
	if err != nil {
		return nil, err
	}
	changeScript, err := txscript.PayToAddrScript(changeAdr)
	if err != nil {
		return nil, err
	}
	changeOut := wire.NewTxOut(amt, changeScript)
	return changeOut, nil
}

// NewAdr creates a new, never before seen address, and increments the
// DB counter as well as putting it in the ram Adrs store, and returns it
func (ts *TxStore) NewAdr() (btcutil.Address, error) {
	var err error
	if ts.Param == nil {
		return nil, fmt.Errorf("NewAdr error: nil param")
	}
	n := uint32(len(ts.Adrs))

	nAdr := ts.GetWalletAddress(n)

	// total number of keys (now +1) into 4 bytes
	var buf bytes.Buffer
	err = binary.Write(&buf, binary.BigEndian, n+1)
	if err != nil {
		return nil, err
	}

	// write to db file
	err = ts.StateDB.Update(func(btx *bolt.Tx) error {
		sta := btx.Bucket(BKTState)
		return sta.Put(KEYNumKeys, buf.Bytes())
	})
	if err != nil {
		return nil, err
	}
	// add in to ram.
	var ma MyAdr
	ma.PkhAdr = nAdr
	ma.KeyIdx = n

	ts.Adrs = append(ts.Adrs, ma)
	if ts.localFilter != nil { // if in hard mode / there is a filter
		ts.localFilter.Add(ma.PkhAdr.ScriptAddress())
	}
	return nAdr, nil
}

// SetDBSyncHeight sets sync height of the db, indicated the latest block
// of which it has ingested all the transactions.
func (ts *TxStore) SetDBSyncHeight(n int32) error {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, n)

	return ts.StateDB.Update(func(btx *bolt.Tx) error {
		sta := btx.Bucket(BKTState)
		return sta.Put(KEYTipHeight, buf.Bytes())
	})
}

// SyncHeight returns the chain height to which the db has synced
func (ts *TxStore) GetDBSyncHeight() (int32, error) {
	var n int32
	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		sta := btx.Bucket(BKTState)
		if sta == nil {
			return fmt.Errorf("no state")
		}
		t := sta.Get(KEYTipHeight)

		if t == nil { // no height written, so 0
			return nil
		}

		// read 4 byte tip height to n
		err := binary.Read(bytes.NewBuffer(t), binary.BigEndian, &n)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// GetAllUtxos returns a slice of all utxos known to the db. empty slice is OK.
func (ts *TxStore) GetAllUtxos() ([]*Utxo, error) {
	var utxos []*Utxo
	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		duf := btx.Bucket(BKTUtxos)
		if duf == nil {
			return fmt.Errorf("no duffel bag")
		}
		return duf.ForEach(func(k, v []byte) error {
			// have to copy k and v here, otherwise append will crash it.
			// not quite sure why but append does weird stuff I guess.

			// create a new utxo
			x := make([]byte, len(k)+len(v))
			copy(x, k)
			copy(x[len(k):], v)
			newU, err := UtxoFromBytes(x)
			if err != nil {
				return err
			}
			// and add it to ram
			utxos = append(utxos, &newU)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return utxos, nil
}

// GetAllStxos returns a slice of all stxos known to the db. empty slice is OK.
func (ts *TxStore) GetAllStxos() ([]*Stxo, error) {
	// this is almost the same as GetAllUtxos but whatever, it'd be more
	// complicated to make one contain the other or something
	var stxos []*Stxo
	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		old := btx.Bucket(BKTStxos)
		if old == nil {
			return fmt.Errorf("no old txos")
		}
		return old.ForEach(func(k, v []byte) error {
			// have to copy k and v here, otherwise append will crash it.
			// not quite sure why but append does weird stuff I guess.

			// create a new stxo
			x := make([]byte, len(k)+len(v))
			copy(x, k)
			copy(x[len(k):], v)
			newS, err := StxoFromBytes(x)
			if err != nil {
				return err
			}
			// and add it to ram
			stxos = append(stxos, &newS)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return stxos, nil
}

// GetTx takes a txid and returns the transaction.  If we have it.
func (ts *TxStore) GetTx(txid *wire.ShaHash) (*wire.MsgTx, error) {
	rtx := wire.NewMsgTx()

	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		txns := btx.Bucket(BKTTxns)
		if txns == nil {
			return fmt.Errorf("no transactions in db")
		}
		txbytes := txns.Get(txid.Bytes())
		if txbytes == nil {
			return fmt.Errorf("tx %s not in db", txid.String())
		}
		buf := bytes.NewBuffer(txbytes)
		return rtx.Deserialize(buf)
	})
	if err != nil {
		return nil, err
	}
	return rtx, nil
}

// GetAllTxs returns all the stored txs
func (ts *TxStore) GetAllTxs() ([]*wire.MsgTx, error) {
	var rtxs []*wire.MsgTx

	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		txns := btx.Bucket(BKTTxns)
		if txns == nil {
			return fmt.Errorf("no transactions in db")
		}

		return txns.ForEach(func(k, v []byte) error {
			tx := wire.NewMsgTx()
			buf := bytes.NewBuffer(v)
			err := tx.Deserialize(buf)
			if err != nil {
				return err
			}
			rtxs = append(rtxs, tx)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return rtxs, nil
}

// GetAllTxids returns all the stored txids. Note that we don't remember
// what height they were at.
func (ts *TxStore) GetAllTxids() ([]*wire.ShaHash, error) {
	var txids []*wire.ShaHash

	err := ts.StateDB.View(func(btx *bolt.Tx) error {
		txns := btx.Bucket(BKTTxns)
		if txns == nil {
			return fmt.Errorf("no transactions in db")
		}

		return txns.ForEach(func(k, v []byte) error {
			txid, err := wire.NewShaHash(k)
			if err != nil {
				return err
			}
			txids = append(txids, txid)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return txids, nil
}

// GetPendingInv returns an inv message containing all txs known to the
// db which are at height 0 (not known to be confirmed).
// This can be useful on startup or to rebroadcast unconfirmed txs.
func (ts *TxStore) GetPendingInv() (*wire.MsgInv, error) {
	// use a map (really a set) do avoid dupes
	txidMap := make(map[wire.ShaHash]struct{})

	utxos, err := ts.GetAllUtxos() // get utxos from db
	if err != nil {
		return nil, err
	}
	stxos, err := ts.GetAllStxos() // get stxos from db
	if err != nil {
		return nil, err
	}

	// iterate through utxos, adding txids of anything with height 0
	for _, utxo := range utxos {
		if utxo.AtHeight == 0 {
			txidMap[utxo.Op.Hash] = struct{}{} // adds to map
		}
	}
	// do the same with stxos based on height at which spent
	for _, stxo := range stxos {
		if stxo.SpendHeight == 0 {
			txidMap[stxo.SpendTxid] = struct{}{}
		}
	}

	invMsg := wire.NewMsgInv()
	for txid := range txidMap {
		item := wire.NewInvVect(wire.InvTypeTx, &txid)
		err = invMsg.AddInvVect(item)
		if err != nil {
			if err != nil {
				return nil, err
			}
		}
	}

	// return inv message with all txids (maybe none)
	return invMsg, nil
}

// PopulateAdrs just puts a bunch of adrs in ram; it doesn't touch the DB
func (ts *TxStore) PopulateAdrs(lastKey uint32) error {
	for k := uint32(0); k < lastKey; k++ {
		var ma MyAdr
		ma.PkhAdr = ts.GetWalletAddress(k)
		ma.KeyIdx = k
		ts.Adrs = append(ts.Adrs, ma)
	}
	return nil
}

func (ts *TxStore) Ingest(tx *wire.MsgTx, height int32) (uint32, error) {
	return ts.IngestMany([]*wire.MsgTx{tx}, height)
}

//TODO !!!!!!!!!!!!!!!111
// IngestMany() is way too long and complicated and ugly.  It's like almost
// 300 lines.  Need to refactor and clean it up / break it up in to little
// pieces

// IngestMany puts txs into the DB atomically.  This can result in a
// gain, a loss, or no result.  Gain or loss in satoshis is returned.
// This function seems too big and complicated.  Maybe can split it up
// or simplify it.
// IngestMany can probably work OK even if the txs are out of order.
// But don't do that, that's weird and untested.
// also it'll error if you give it more than 1M txs, so don't.
func (ts *TxStore) IngestMany(txs []*wire.MsgTx, height int32) (uint32, error) {
	var hits uint32
	var err error
	var nUtxoBytes [][]byte // serialized new utxos to store

	cachedShas := make([]*wire.ShaHash, len(txs)) // cache every txid

	hitTxs := make([]bool, len(txs)) // keep track of which txs to store

	// not worth making a struct but these 2 go together
	spentOPs := make([][]byte, 0, len(txs)) // at least 1 txin per tx
	// spendTxIdx tells which tx (in the txs slice) the utxo loss came from
	spentTxIdx := make([]uint32, 0, len(txs))

	if len(txs) < 1 || len(txs) > 1000000 {
		return 0, fmt.Errorf("tried to ingest %d txs, expect 1 to 1M", len(txs))
	}

	// initial in-ram work on all txs.
	for i, tx := range txs {
		// tx has been OK'd by SPV; check tx sanity
		utilTx := btcutil.NewTx(tx) // convert for validation
		// checks basic stuff like there are inputs and ouputs
		err = blockchain.CheckTransactionSanity(utilTx)
		if err != nil {
			return hits, err
		}
		// cache all txids
		cachedShas[i] = utilTx.Sha()
		// before entering into db, serialize all inputs of ingested txs
		for _, txin := range tx.TxIn {
			spentOPs = append(spentOPs, OutPointToBytes(txin.PreviousOutPoint))
			spentTxIdx = append(spentTxIdx, uint32(i)) // save tx it came from
		}
	}

	// go through txouts, and then go through addresses to match

	// generate PKscripts for all addresses
	wPKscripts := make([][]byte, len(ts.Adrs))
	aPKscripts := make([][]byte, len(ts.Adrs))

	for i, _ := range wPKscripts {
		// iterate through all our addresses
		// convert regular address to witness address.  (split adrs later)
		oa, err := btcutil.NewAddressPubKeyHash(
			ts.Adrs[i].PkhAdr.ScriptAddress(), ts.Param)
		if err != nil {
			return hits, err
		}

		wPKscripts[i], err = txscript.PayToAddrScript(ts.Adrs[i].PkhAdr)
		if err != nil {
			return hits, err
		}
		aPKscripts[i], err = txscript.PayToAddrScript(oa)
		if err != nil {
			return hits, err
		}
	}

	// iterate through all outputs of this tx, see if we gain utxo (in ram)
	// stash serialized copies of all new utxos, which we add to db later.
	// not sure how bolt works in terms of sorting.  Faster to sort here
	// or let bolt sort it?
	for i, tx := range txs {
		for j, out := range tx.TxOut {
			for k, ascr := range aPKscripts {
				// detect p2wpkh
				spendableBy := int32(0)
				if bytes.Equal(out.PkScript, wPKscripts[k]) {
					spendableBy = 1
				}
				if bytes.Equal(out.PkScript, ascr) || spendableBy == 1 { // found one
					var newu Utxo // create new utxo and copy into it
					newu.AtHeight = height
					newu.KeyIdx = ts.Adrs[k].KeyIdx
					newu.Value = out.Value
					newu.SpendLag = spendableBy // 1 for witness
					var newop wire.OutPoint
					newop.Hash = *cachedShas[i]
					newop.Index = uint32(j)
					newu.Op = newop
					b, err := newu.ToBytes()
					if err != nil {
						return hits, err
					}
					nUtxoBytes = append(nUtxoBytes, b)
					hits++
					hitTxs[i] = true
					break // txos can match only 1 script
				}
			}
		}
	}

	// now do the db write (this is the expensive / slow part)
	err = ts.StateDB.Update(func(btx *bolt.Tx) error {
		// get all 4 buckets
		duf := btx.Bucket(BKTUtxos)
		//		sta := btx.Bucket(BKTState)
		old := btx.Bucket(BKTStxos)
		txns := btx.Bucket(BKTTxns)

		// check if the tx we're ingesting is a funding tx we know the txid of,
		// but haven't seen yet.  This means iterating through peer buckets.
		// This basically copies code in chandb.go so it's a little ugly,
		// merge/cleanup later.
		// Also check if this tx SPENDS a multisig outpoint we know of.
		prs := btx.Bucket(BKTPeers)
		if prs != nil { // there are peers, check this TX for chan/mult
			err = prs.ForEach(func(idPub, nothin []byte) error {
				if nothin != nil {
					return nil // non-bucket
				}
				pr := prs.Bucket(idPub) // go into this peer's bucket
				pIdx := BtU32(pr.Get(KEYIdx))
				if pIdx == 0 {
					return fmt.Errorf("Peer %x has no index", idPub)
				}
				//TODO optimization: could only check 0conf channels,
				// or ignore 0conf and only accept spv proofs.
				// Then we could only look for the spentOP hash, so that
				// Ingest() only detects channel closes.
				return pr.ForEach(func(qcOpBytes, nthin []byte) error {
					if nthin != nil {
						//	fmt.Printf("val %x\n", nthin)
						return nil // non-bucket / outpoint
					}
					qchanBucket := pr.Bucket(qcOpBytes)
					if qchanBucket == nil {
						return nil // nothing stored / not a bucket
					}
					// found a channel, deserialize part of it.
					// this is not the full channel data; only using the
					// outpoint.  full data will be loaded if we need it
					// (when the channel is getting closed.)
					hitQChan, err := QchanFromBytes(qchanBucket.Get(KEYutxo))
					if err != nil {
						return err
					}
					hitQChan.PeerIdx = pIdx
					// will need state to see if grabbable
					hitQChan.State, err = StatComFromBytes(qchanBucket.Get(KEYState))
					if err != nil {
						return err
					}

					// check if we gain a known txid but unknown tx
					for i, txid := range cachedShas {
						if txid.IsEqual(&hitQChan.Op.Hash) {
							// hit; ingesting tx which matches chan/multi
							// all we do is assign height and increment hits
							// (which will save the tx)
							hitTxs[i] = true
							hitQChan.Utxo.AtHeight = height
							qcBytes, err := hitQChan.ToBytes()
							if err != nil {
								return err
							}
							// save multiout in the bucket
							err = qchanBucket.Put(KEYutxo, qcBytes)
							if err != nil {
								return err
							}
						}
					}
					// check if it's spending the multiout
					// there's some problem here as it doesn't always detect it
					// properly...? still has this problem....
					for i, spentOP := range spentOPs {
						if bytes.Equal(spentOP, qcOpBytes) {
							// this multixo is now spent.
							hitTxs[spentTxIdx[i]] = true
							// set qchan's spending txid and height
							hitQChan.CloseData.CloseTxid = *cachedShas[spentTxIdx[i]]
							hitQChan.CloseData.CloseHeight = height
							hitQChan.CloseData.Closed = true
							// serialize
							closeBytes, err := hitQChan.CloseData.ToBytes()
							if err != nil {
								return err
							}

							// need my pubkey too
							hitQChan.MyRefundPub = ts.GetRefundPubkey(
								pIdx, hitQChan.KeyIdx)

							// save to close bucket
							err = qchanBucket.Put(KEYqclose, closeBytes)
							if err != nil {
								return err
							}
							// generate utxos from the close tx, if any.
							ctxos, err := hitQChan.GetCloseTxos(txs[spentTxIdx[i]])
							if err != nil {
								return err
							}
							// serialize utxos to save later
							for _, ctxo := range ctxos {
								b, err := ctxo.ToBytes()
								if err != nil {
									return err
								}
								nUtxoBytes = append(nUtxoBytes, b)
							}
						}
					}
					return nil
				})
			})
			if err != nil {
				return err
			}
			// end of peer checking
		}

		// first gain, then lose
		// add all new utxos to db, this is quick as the work is above
		for _, ub := range nUtxoBytes {
			err = duf.Put(ub[:36], ub[36:])
			if err != nil {
				return err
			}
		}

		// iterate through duffel bag and look for matches
		// this makes us lose money, which is regrettable, but we need to know.
		// could lose stuff we just gained, that's OK.
		for i, nOP := range spentOPs {
			v := duf.Get(nOP)
			if v != nil {
				hitTxs[spentTxIdx[i]] = true
				// do all this just to figure out value we lost
				x := make([]byte, len(nOP)+len(v))
				copy(x, nOP)
				copy(x[len(nOP):], v)
				lostTxo, err := UtxoFromBytes(x)
				if err != nil {
					return err
				}

				// after marking for deletion, save stxo to old bucket
				var st Stxo                               // generate spent txo
				st.Utxo = lostTxo                         // assign outpoint
				st.SpendHeight = height                   // spent at height
				st.SpendTxid = *cachedShas[spentTxIdx[i]] // spent by txid
				stxb, err := st.ToBytes()                 // serialize
				if err != nil {
					return err
				}
				err = old.Put(nOP, stxb) // write nOP:v outpoint:stxo bytes
				if err != nil {
					return err
				}

				err = duf.Delete(nOP)
				if err != nil {
					return err
				}
			}
		}
		// save all txs with hits
		for i, tx := range txs {
			if hitTxs[i] == true {
				hits++
				var buf bytes.Buffer
				tx.Serialize(&buf) // always store witness version
				err = txns.Put(cachedShas[i].Bytes(), buf.Bytes())
				if err != nil {
					return err
				}
			}
		}
		return nil
	})

	fmt.Printf("ingest %d txs, %d hits\n", len(txs), hits)
	return hits, err
}
