package uspv

import "github.com/boltdb/bolt"

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
		chn := btx.Bucket(BKTChnls)
		key := outPointToBytes(s.FundPoint)
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
