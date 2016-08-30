package qln

import "github.com/boltdb/bolt"

func (nd *LnNode) Init(dbfilename string, basewal UWallet) error {
	nd.BaseWallet = basewal

	err := nd.OpenDB(dbfilename)
	if err != nil {
		return err
	}
	nd.OmniChan = make(chan []byte, 10)
	go nd.OmniHandler()

	return nil
}

// Opens the DB file for the LnNode
func (nd *LnNode) OpenDB(filename string) error {
	var err error

	nd.LnDB, err = bolt.Open(filename, 0644, nil)
	if err != nil {
		return err
	}
	// create buckets if they're not already there
	err = nd.LnDB.Update(func(btx *bolt.Tx) error {
		_, err := btx.CreateBucketIfNotExists(BKTPeers)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
