package uspv

import (
	"bytes"
	"fmt"

	"github.com/boltdb/bolt"
	"github.com/btcsuite/btcd/btcec"
)

var (
	BKTChnls = []byte("Chanls") // leave the rest to collect interest
)

// NewAdr creates a new, never before seen address, and increments the
// DB counter as well as putting it in the ram Adrs store, and returns it
func (ts *TxStore) SaveChanState(s SimplChannel) error {

	s.FundPoint.Hash.Bytes()

	var err error
	// write to db file
	err = ts.StateDB.Update(func(btx *bolt.Tx) error {
		//		chn := btx.Bucket(BKTChnls)
		//		key := outPointToBytes(s.FundPoint)
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// store a MultiSig output
func (ts *TxStore) SaveMultiOut(m MultiOut) error {
	err := ts.StateDB.Update(func(btx *bolt.Tx) error {
		chn, _ := btx.CreateBucketIfNotExists(BKTChnls) // only errs on name
		mBytes, err := m.ToBytes()
		if err != nil {
			return err
		}
		chn.Put(mBytes[:36], mBytes[36:])
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
		chn := btx.Bucket(BKTChnls)
		if chn == nil {
			return nil
		}
		return chn.ForEach(func(k, v []byte) error {
			// have to copy k and v here, otherwise append will crash it.
			// not quite sure why but append does weird stuff I guess.
			x := make([]byte, len(k)+len(v))
			copy(x, k)
			copy(x[len(k):], v)
			newMult, err := MultiOutFromBytes(x)
			if err != nil {
				return err
			}
			// and add it to ram
			multis = append(multis, &newMult)
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
// the first 53 bytes are the utxo, then the next 33 is the pubkey
func MultiOutFromBytes(b []byte) (MultiOut, error) {
	var m MultiOut

	if len(b) < 86 {
		return m, fmt.Errorf("Got %d bytes for MultiOut, expect 86", len(b))
	}

	u, err := UtxoFromBytes(b[:53])
	if err != nil {
		return m, err
	}
	m.Utxo = u // assign the utxo

	m.TheirPub, err = btcec.ParsePubKey(b[53:], btcec.S256())
	if err != nil {
		return m, err
	}
	return m, nil
}
