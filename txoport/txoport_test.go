package txoport

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// TestHardCoded tries compressing / decompressing hardcoded sigs
func TestHardCoded(t *testing.T) {
	var u1 PortUtxo

	b1, err := u1.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("b1: %x\n", b1)

	u2, err := PortUtxoFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}

	u2.NetID = chaincfg.TestNet3Params.PrivateKeyID
	u2.Op.Hash = wire.DoubleSha256SH([]byte("test"))
	u2.Op.Index = 3
	u2.Amt = 1234567890
	u2.Mode = TxoP2PKHComp
	u2.Seq = 65535
	u2.KeyPath.Depth = 3
	u2.KeyPath.Level[0] = 0x8000002C
	u2.KeyPath.Level[1] = 1
	u2.KeyPath.Level[2] = 0x80000000

	//	u2.PrivKey[0] = 0x11
	u2.PkScript = []byte("1234567890123456")
	b2, err := u2.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("b2: %x\n", b2)
	u3, err := PortUtxoFromBytes(b2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("u2: %s", u2.String())
	t.Logf("u3: %s", u3.String())
	if !u2.Equal(u3) {
		t.Fatalf("u2, u3 should be the same")
	}

}
