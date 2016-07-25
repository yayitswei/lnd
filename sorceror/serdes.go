package sorceror

import (
	"bytes"
	"encoding/binary"
)

// Descriptors are 96 bytes
// PKH 20
// Delay 2
// Fee 8
// HAKDbase 33
// Timebase 33

// ToBytes turns a SorceDescriptor into 96 bytes
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
func SorceDescriptorFromBytes(b []byte) (SorceDescriptor, error) {
	buf := bytes.NewBuffer(b)
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

// SorceMsgs are 128 bytes.
// txid 32
// elk 32
// sig 64
// ToBytes turns a SorceMsg into 128 bytes
func (sm *SorceMsg) ToBytes() []byte {
	var buf bytes.Buffer
	buf.Write(sm.Txid.Bytes())
	buf.Write(sm.Elk.Bytes())
	buf.Write(sm.Sig[:])
	return buf.Bytes()
}

// SorceMsgFromBytes turns 128 bytes into a SorceMsg
func SorceMsgFromBytes(b []byte) SorceMsg {
	buf := bytes.NewBuffer(b)
	var sm SorceMsg
	copy(sm.Txid[:], buf.Next(32))
	copy(sm.Elk[:], buf.Next(32))
	copy(sm.Sig[:], buf.Next(64))
	return sm
}

// SorceStates are 100 bytes
// txid 32
// sig 64
// xtra 4
// ToBytes turns a SorceState into 100 bytes
func (ss *SorceState) ToBytes() []byte {
	var buf bytes.Buffer
	buf.Write(ss.Txid.Bytes())
	buf.Write(ss.Sig[:])
	buf.Write(ss.xtra[:])
	return buf.Bytes()
}

// SorceStateFromBytes turns 100 bytes into a SorceState
func SorceStateFromBytes(b []byte) SorceState {
	buf := bytes.NewBuffer(b)
	var ss SorceState
	copy(ss.Txid[:], buf.Next(32))
	copy(ss.Sig[:], buf.Next(64))
	copy(ss.xtra[:], buf.Next(4))
	return ss
}
