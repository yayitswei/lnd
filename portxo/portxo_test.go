package portxo

import (
	"testing"

	"github.com/roasbeef/btcd/wire"
)

// TestHardCoded tries compressing / decompressing hardcoded sigs
func TestHardCoded(t *testing.T) {
	var u1 PorTxo

	b1, err := u1.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	u2, err := PorTxoFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}

	u2.Op.Hash = wire.DoubleSha256SH([]byte("test"))
	u2.Op.Index = 3
	u2.Value = 1234567890
	u2.Mode = TxoP2PKHComp
	u2.Seq = 65535
	u2.KeyGen.Depth = 3
	u2.KeyGen.Step[0] = 0x8000002C
	u2.KeyGen.Step[1] = 1
	u2.KeyGen.Step[2] = 0x80000000

	//	u2.PrivKey[0] = 0x11
	u2.PkScript = []byte("1234567890123456")
	b2, err := u2.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	u3, err := PorTxoFromBytes(b2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("b2: %x\n", b2)

	t.Logf("u2: %s", u2.String())

	b3, err := u3.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("b3: %x\n", b3)

	t.Logf("u3: %s", u3.String())
	if !u2.Equal(u3) {
		t.Fatalf("u2, u3 should be the same")
	}

}
