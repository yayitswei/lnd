package uwire

import (
	"bytes"
	"encoding/binary"
	"fmt"

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

// ToBytes turns a PubResponse into some bytes. var-lenght sig at end
func PubKeyResponse(pub *btcec.PublicKey) ([]byte, error) {
	var buf bytes.Buffer
	// write 1 byte header
	err := buf.WriteByte(MSGID_PUBRESP)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(pub.SerializeCompressed()) // write 33 byte pubkey
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func PubResponseFromBytes(b []byte) (*btcec.PublicKey, error) {
	if len(b) != 34 {
		return nil, fmt.Errorf("PubResponse %d bytes, expect 34", len(b))
	}
	if b[0] != MSGID_PUBRESP {
		return nil, fmt.Errorf("not pubresponse, got msgid %x", b[0])
	}
	pub, err := btcec.ParsePubKey(b[1:], btcec.S256())
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// ToBytes turns a FundDetails into some bytes.
func (m *MultiDesc) ToBytes() ([]byte, error) {
	var buf bytes.Buffer
	// write 1 byte header
	err := buf.WriteByte(MSGID_MULTIDESC)
	if err != nil {
		return nil, err
	}
	// write 8 byte channel capacity
	err = binary.Write(&buf, binary.BigEndian, m.Amt)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(m.MultiPub.SerializeCompressed()) // write 33 byte pubkey
	if err != nil {
		return nil, err
	}
	// write 32 byte txid
	_, err = buf.Write(m.FundPoint.Hash.Bytes())
	if err != nil {
		return nil, err
	}
	// write 4 byte output index
	err = binary.Write(&buf, binary.BigEndian, m.FundPoint.Index)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ChanDescFromBytes makes channel description from some bytes.
func MultiDescFromBytes(b []byte) (*MultiDesc, error) {
	m := new(MultiDesc)
	if b == nil {
		return nil, fmt.Errorf("nil input slice")
	}
	buf := bytes.NewBuffer(b)
	if buf.Len() < 77 {
		return nil, fmt.Errorf("Got %d bytes for utxo, expect < 97", buf.Len())
	}
	// read msgid
	id, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	if id != MSGID_MULTIDESC {
		return nil, fmt.Errorf("Not identified as MultiDesc")
	}
	// read 8 byte channel capacity
	err = binary.Read(buf, binary.BigEndian, &m.Amt)
	if err != nil {
		return nil, err
	}
	// read 33 byte pubkey
	m.MultiPub, err = btcec.ParsePubKey(buf.Next(33), btcec.S256())
	if err != nil {
		return nil, err
	}
	// read 32 byte txid
	err = m.FundPoint.Hash.SetBytes(buf.Next(32))
	if err != nil {
		return nil, err
	}
	// read 4 byte output index
	err = binary.Read(buf, binary.BigEndian, &m.FundPoint.Index)
	if err != nil {
		return nil, err
	}

	return m, nil
}
