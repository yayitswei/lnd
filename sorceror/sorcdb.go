package sorceror

import (
	"github.com/boltdb/bolt"
	"github.com/btcsuite/btcd/wire"
)

/*
SorceDB has 3 top level buckets -- 2 small ones and one big one.

PKHMapBucket is k:v
channelIndex : PKH

ChannelBucket is k:v
PKH
  |
  |-KEYElkRcv : Serialized elkrem receiver (couple KB)
  |
  |-KEYIdx : channelIdx (4 bytes)
  |
  |-KEYStatic : ChanStatic (~100 bytes)

(could also add some metrics, like last write timestamp)

the big one:

TxidBucket is k:v
Txid : IdxSig (74 bytes)

Leave as is for now, but could modify the txid to make it smaller.  Could
HMAC it with a local key to prevent collision attacks and get the txid size down
to 8 bytes or so.  An issue is then you can't re-export the states to other nodes.
Only reduces size by 24 bytes, or about 20%.  Hm.  Try this later.

... actually the more I think about it, this is an easy win.
Also collision attacks seem ineffective; even random false positives would
be no big deal, just a couple ms of CPU to compute the grab tx and see that
it doesn't match.


To save another couple bytes could make the idx in the idxsig varints.
Only a 3% savings and kindof annoying so will leave that for now.


*/

var (
	BUCKETPKHMap   = []byte("pkm") // bucket for idx:pkh mapping
	BUCKETChandata = []byte("cda") // bucket for channel data (elks, points)
	BUCKETTxid     = []byte("txi") // big bucket with every txid

	KEYStatic = []byte("sta") // static per channel data as value
	KEYElkRcv = []byte("elk") // elkrem receiver
	KEYIdx    = []byte("idx") // index mapping
)

// CheckTxids takes a slice of txids and sees if any are in the
// DB.  If there is, SorceMsgs are returned which can then be turned into txs.
// can take the txid slice direct from a msgBlock after block has been
// merkle-checked.
func (s *SorceStore) CheckTxids(inTxids []wire.ShaHash) ([]SorceMsg, error) {
	var hitTxids []SorceMsg
	err := s.SorceDB.View(func(btx *bolt.Tx) error {
		bkt := btx.Bucket(BUCKETTxid)
		for _, txid := range inTxids {
			idxsig := bkt.Get(txid.Bytes())
			if idxsig != nil { // hit!!!!1 whoa!
				// Call SorceMsg construction function here
				var sm SorceMsg
				sm.Txid = txid
				// that wasn't it.  make a real function

				hitTxids = append(hitTxids, sm)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return hitTxids, nil
}
