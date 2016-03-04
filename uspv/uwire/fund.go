package uwire

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
)

// note in uwire there is no real "funding request", you just ask
// the acceptor for a pubkey.
// if the acceptor gives a QR code or otherwise includes a pubkey
// in their request for payment, the fund request and response can be
// omitted entirely and the channel funder can start with FundDetails.

// ChanDesc lets the acceptor know what the channel looks like
type ChanDesc struct {
	Capacity  uint64           // how much funder puts in to channel
	MultiPub  *btcec.PublicKey // funder's multisig pubkey
	FundPoint wire.OutPoint
}

// ToBytes turns a FundDetails into some bytes.
func (c *ChanDesc) ToBytes() ([]byte, error) {
	var buf bytes.Buffer
	// write 1 byte header
	err := buf.WriteByte(MSGID_CHANDESC)
	if err != nil {
		return nil, err
	}
	// write 8 byte channel capacity
	err = binary.Write(&buf, binary.BigEndian, c.Capacity)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(c.MultiPub.SerializeCompressed()) // write 33 byte pubkey
	if err != nil {
		return nil, err
	}
	// write 32 byte txid
	_, err = buf.Write(c.FundPoint.Hash.Bytes())
	if err != nil {
		return nil, err
	}
	// write 4 byte output index
	err = binary.Write(&buf, binary.BigEndian, c.FundPoint.Index)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ChanDescFromBytes makes channel description from some bytes.
func ChanDescFromBytes(b []byte) (*ChanDesc, error) {
	c := new(ChanDesc)
	if b == nil {
		return nil, fmt.Errorf("nil input slice")
	}
	buf := bytes.NewBuffer(b)
	if buf.Len() < 77 {
		return nil, fmt.Errorf("Got %d bytes for utxo, expect < 97", buf.Len())
	}
	// read 8 byte channel capacity
	err := binary.Read(buf, binary.BigEndian, &c.Capacity)
	if err != nil {
		return nil, err
	}
	// read 33 byte pubkey
	c.MultiPub, err = btcec.ParsePubKey(buf.Next(33), btcec.S256())
	if err != nil {
		return nil, err
	}
	// read 32 byte txid
	err = c.FundPoint.Hash.SetBytes(buf.Next(32))
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.BigEndian, &c.FundPoint.Index)
	if err != nil {
		return nil, err
	}

	return c, nil
}
