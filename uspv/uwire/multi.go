package uwire

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
)

// MutliDesc describes a multi-sig p2wsh output the funder has made.
// It's similar to ChannelDescription.  Kindof the same really.

// PubRequest is just a single header byte, no need for a struct.

// PubResponse is just a pubkey.  Also don't need a struct.

// MultiDesc advertises that a multisig output has been created.
type MultiDesc struct {
	Amt       uint64           // how much the funder put in
	MultiPub  *btcec.PublicKey // funder's multisig pubkey
	FundPoint wire.OutPoint    // txid and index
}
