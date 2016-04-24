package uwire

import (
	"bytes"
	"encoding/binary"
)

type SigPush struct {
	SendAmt   uint32   // amount being pushed with this state update (delta)
	RevocHash [20]byte // Hash of the next state revocation to use
	Sig       []byte   // Signature for the new Commitment
}

type SigRevPull struct {
	RevocHash [20]byte // Hash of the next state revocation to use
	Revoc     [32]byte // 32 byte hash fed into elkrem receiver
	Sig       []byte   // Signature for the new Commitment
}

type RevPush struct {
	Revoc [32]byte // revocation is a 32 byte hash fed into elkrem receiver
}

// ToBytes turns a SigPush into some bytes.  Sig at end because varia-length
func (s *SigPush) ToBytes() ([]byte, error) {
	var buf bytes.Buffer
	// write 1 byte header
	err := buf.WriteByte(MSGID_SIGPUSH)
	if err != nil {
		return nil, err
	}
	// write the 8 byte amount being pushed
	err = binary.Write(&buf, binary.BigEndian, s.SendAmt)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(s.RevocHash[:]) // write 20 byte hash H
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(s.Sig) // write 70ish byte sig
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ToBytes turns a SigPull into some bytes.
func (s *SigPull) ToBytes() ([]byte, error) {
	var buf bytes.Buffer
	// write 1 byte header
	err := buf.WriteByte(MSGID_SIGPULL)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(s.RevocHash[:]) // write 20 byte hash H
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(s.Sig) // write 70ish byte sig
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ToBytes turns a Revoc into some bytes.  Can't fail.
func (r *Revoc) ToBytes() []byte {
	return append([]byte{MSGID_REVOC}, r[:]...)
}
