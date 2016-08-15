package txoport

import "testing"

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
	t.Logf("u2: %s", u2.String())

	u2.Amt = 1234567890
	u2.Mode = TxoModeP2PKHComp
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

	u3, err := PortUtxoFromBytes(b2)
	if err != nil {
		t.Fatal(err)
	}
	if !u2.Equal(u3) {
		t.Fatalf("u2, u3 should be the same")
	}
	t.Logf("u3: %s", u3.String())
}
