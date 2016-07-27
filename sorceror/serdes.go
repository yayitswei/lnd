package sorceror

import (
	"bytes"
	"encoding/binary"
)

// Descriptors are 96 bytes
// ChanId 4
// PKH 20
// Delay 2
// Fee 8
// HAKDbase 33
// Timebase 33

// ToBytes turns a SorceDescriptor into 100 bytes
func (sd *SorceDescriptor) ToBytes() []byte {
	var buf bytes.Buffer
	buf.Write(sd.DestPKHScript[:])
	binary.Write(&buf, binary.BigEndian, sd.Delay)
	binary.Write(&buf, binary.BigEndian, sd.Fee)
	buf.Write(sd.HAKDBasePoint[:])
	buf.Write(sd.TimeBasePoint[:])
	return buf.Bytes()
}

// SorceDescriptorFromBytes turns 96 bytes into a SorceDescriptor
func SorceDescriptorFromBytes(b [96]byte) (SorceDescriptor, error) {
	buf := bytes.NewBuffer(b[:])
	var sd SorceDescriptor

	copy(sd.DestPKHScript[:], buf.Next(20))
	err := binary.Read(buf, binary.BigEndian, &sd.Delay)
	if err != nil {
		return sd, err
	}
	err = binary.Read(buf, binary.BigEndian, &sd.Fee)
	if err != nil {
		return sd, err
	}

	copy(sd.HAKDBasePoint[:], buf.Next(33))
	copy(sd.TimeBasePoint[:], buf.Next(33))

	return sd, nil
}

// SorceMsgs are 148 bytes.
// PKH 20
// txid 32
// elk 32
// sig 64
// ToBytes turns a SorceMsg into 148 bytes
func (sm *SorceMsg) ToBytes() (b [148]byte) {
	var buf bytes.Buffer
	buf.Write(sm.DestPKHScript[:])
	buf.Write(sm.Txid.Bytes())
	buf.Write(sm.Elk.Bytes())
	buf.Write(sm.Sig[:])
	copy(b[:], buf.Bytes())
	return
}

// SorceMsgFromBytes turns 128 bytes into a SorceMsg
func SorceMsgFromBytes(b [128]byte) SorceMsg {
	var sm SorceMsg
	copy(sm.Txid[:], b[32:])
	copy(sm.Elk[:], b[32:64])
	copy(sm.Sig[:], b[64:])
	return sm
}

// IdxSigs are 74 bytes
// PKHIdx 4
// StateIdx 6
// Sig 64
type IdxSig struct {
	PKHIdx   uint32
	StateIdx uint64
	Sig      [64]byte
}
