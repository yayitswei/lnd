package uspv

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/boltdb/bolt"
	"github.com/btcsuite/btcd/btcec"
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
	|-0x00000000 - bucket 0 (channel)
		|
		|-CID: channelID
		|
		|-channel state data


Right now these buckets are all in one boltDB.  This limits it to one db write
at a time, which for super high thoughput could be too slow.
Later on we can chop it up so that each channel gets it's own db file.

*/

var (
	BKTPeers   = []byte("Peer") // all peer data is in this bucket.
	KEYElkRecv = []byte("ElkR") // indicates elkrem receiver
	KEYPeerIdx = []byte("Pdx")  // indicates elkrem receiver
)

// I shouldn't even have to write these...

// 4 byte slice to uin32.  Returns 0 if something doesn't work.
func BtU32(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	var i uint32
	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.BigEndian, i)
	return i
}

// uint32 to 4 bytes.  Always works.
func U32tB(i uint32) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, i)
	return buf.Bytes()
}

// NewPeer saves a pubkey in the DB and assigns a peer index.  Call this
// the first time you connect to someone.
func (ts *TxStore) NewPeer(pub *btcec.PublicKey) error {
	return ts.StateDB.Update(func(btx *bolt.Tx) error {
		prs, _ := btx.CreateBucketIfNotExists(BKTPeers) // only errs on name

		newPeerIdx := prs.Stats().KeyN // know this many peers already

		pr, err := prs.CreateBucket(pub.SerializeCompressed())
		if err != nil {
			return err // peer already exists
		}

		var buf bytes.Buffer
		// write 4 byte peer index
		err = binary.Write(&buf, binary.BigEndian, newPeerIdx)
		if err != nil {
			return err
		}
		return pr.Put(KEYPeerIdx, buf.Bytes())
	})
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
		idx = BtU32(pr.Get(KEYPeerIdx))
		return nil
	})
	return idx, err
}

// store a MultiSig output
func (ts *TxStore) NewMultReq(m MultiOut) error {
	err := ts.StateDB.Update(func(btx *bolt.Tx) error {

		return nil
	})
	if err != nil {
		return err
	}

	return nil
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
			var peerIdx uint32
			pr := prs.Bucket(idPub) // go into this peer's bucket
			peerIdx = BtU32(pr.Get(KEYPeerIdx))

			return pr.ForEach(func(MultIdxBytes, pubkey []byte) error {
				multIdx := BtU32(MultIdxBytes) // copy here safe...?
				x := make([]byte, len(MultIdxBytes)+len(pubkey))
				copy(x, MultIdxBytes)
				copy(x[len(MultIdxBytes):], pubkey)
				newMult, err := MultiOutFromBytes(x)
				if err != nil {
					return err
				}
				newMult.PeerIdx = peerIdx
				newMult.MultIdx = multIdx
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

	// write per-peer multiOut index (4 bytes)
	err = binary.Write(&buf, binary.BigEndian, m.MultIdx)
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
// the first 53 bytes are the utxo, then 4 idx, then next 33 is the pubkey
func MultiOutFromBytes(b []byte) (MultiOut, error) {
	var m MultiOut

	if len(b) < 90 {
		return m, fmt.Errorf("Got %d bytes for MultiOut, expect 90", len(b))
	}

	u, err := UtxoFromBytes(b[:53])
	if err != nil {
		return m, err
	}

	buf := bytes.NewBuffer(b[53:])
	// will be 37, size checked up there

	m.Utxo = u // assign the utxo

	// read 4 byte outpoint index within the tx to spend
	err = binary.Read(buf, binary.BigEndian, &m.MultIdx)
	if err != nil {
		return m, err
	}

	m.TheirPub, err = btcec.ParsePubKey(buf.Bytes(), btcec.S256())
	if err != nil {
		return m, err
	}
	return m, nil
}
