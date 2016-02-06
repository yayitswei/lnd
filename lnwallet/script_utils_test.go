package lnwallet

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcrpcclient"
	"github.com/btcsuite/btcutil"
)

var (
	bobPrivKey = []byte{
		0x81, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x63, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0xd, 0xe7, 0x95, 0xe4, 0xb7, 0x25, 0xb8, 0x4d,
		0x1e, 0xb, 0x4c, 0xfd, 0x9e, 0xc5, 0x8c, 0xe9,
	}
	alicePrivKey = []byte{
		0x81, 0xb9, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x63, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0xd1, 0xe7, 0x95, 0xe4, 0xb7, 0x25, 0xb8, 0x4d,
		0x1d, 0xb, 0x4c, 0xfd, 0x9e, 0xc5, 0x8c, 0xe9,
	}
	revokePreImage = []byte{
		0x81, 0xb9, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x63, 0x5a, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0xd1, 0xe7, 0x95, 0xe4, 0xb7, 0x25, 0xb8, 0x4d,
		0x1d, 0xb, 0x4b, 0xfd, 0x9e, 0xc5, 0x8c, 0xe9,
	}
)

func TestCSVCommitmentTransaction(t *testing.T) {
	// Connect to the already running Bitcoin Core node, which is in regest
	// mode.
	rpcConfig := btcrpcclient.ConnConfig{
		Host:         "localhost:18332",
		User:         "",
		Pass:         "",
		DisableTLS:   true,
		HTTPPostMode: true,
	}
	rpcClient, err := btcrpcclient.New(&rpcConfig, nil)
	if err != nil {
		t.Fatalf("unable to create rpc client: %v", err)
	}
	defer rpcClient.Shutdown()

	activeNet := &chaincfg.RegressionNetParams

	// Create two keys.
	alicePriv, alicePub := btcec.PrivKeyFromBytes(btcec.S256(), bobPrivKey[:])
	bobPriv, bobPub := btcec.PrivKeyFromBytes(btcec.S256(), alicePrivKey[:])

	// At this point, using the command-line in regtest mode, give alice a
	// 10 BTC output spendable with the above WIF key.
	aliceAddrPk, err := btcutil.NewAddressPubKey(alicePub.SerializeCompressed(),
		activeNet)
	if err != nil {
		t.Fatalf("unable to create pk address for alice: %v", err)
	}
	aliceAddr := aliceAddrPk.AddressPubKeyHash()
	aliceOutputScript, err := txscript.PayToAddrScript(aliceAddr)
	if err != nil {
		t.Fatalf("unable to create alice p2pkh script: %v", err)
	}

	aliceOutputAmt := btcutil.Amount(10e8)

	// Fill in the txid, output # of the created output.
	createTxidStr := "f79e0b5d0db470e65402328d77c1e81632e7ba8534437a41836023747063329b"
	createdTxid, err := wire.NewShaHashFromStr(createTxidStr)
	if err != nil {
		t.Fatalf("unable to parse txid: %v", err)
	}
	aliceTxin := &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *createdTxid,
			Index: 1,
		},
	}

	// Create commitment tx (initial state).
	// We'll create a fake revocation hash using the pre-image above. Finally,
	// we set the relative locktime for CSV to 3 blocks. Under this scenario,
	// Bob will need to wait 3 blocks AFTER the commitment txn hits a block
	// before he'll be able to spend his output.
	revokeHash := btcutil.Hash160(revokePreImage)
	csvTimeout := lockTimeToSequence(false, 3)
	commitmentTx, err := createCommitTx(aliceTxin, bobPub, alicePub, revokeHash,
		csvTimeout, aliceOutputAmt/2, aliceOutputAmt/2)
	if err != nil {
		t.Fatalf("unable to create commit tx: %v", err)
	}

	// Sign the commitment txn with alice's key, then broadcast to our
	// running regtest node.
	sigScript, err := txscript.SignatureScript(commitmentTx, 0,
		aliceOutputScript, txscript.SigHashAll, alicePriv, true)
	if err != nil {
		t.Fatalf("unable to sign alice input for commit tx with alice's "+
			"key: %v", err)
	}
	commitmentTx.TxIn[0].SignatureScript = sigScript

	fundTxid, err := rpcClient.SendRawTransaction(commitmentTx, true)
	if err != nil {
		t.Fatalf("unable to broadcast commit txn to node: %v", err)
	}

	// Mine a single block, this'll include the commitment transaction
	// created above.
	// 3 blocks until Bob can spend.
	if _, err := rpcClient.Generate(1); err != nil {
		t.Fatalf("unable to mine block: %v", err)
	}

	// Alice's output is unencumbered, so she should be able to spend it
	// immediately. To test this, we create, sign, then broadcast a new tx
	// which spends the second output on the commitment tx to a new output
	// controllled by alice.
	aliceSpendTx := wire.NewMsgTx()
	aliceSpendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *fundTxid,
			Index: 1,
		},
	})
	aliceSpendTx.AddTxOut(&wire.TxOut{
		Value:    4e8,
		PkScript: aliceOutputScript,
	})

	toAliceScript, err := commitScriptUnencumbered(alicePub)
	if err != nil {
		t.Fatalf("unable to re-generate redeem script for alice: %v", err)
	}

	aliceSig, err := txscript.RawTxInSignature(aliceSpendTx, 0,
		toAliceScript, txscript.SigHashAll, alicePriv)
	if err != nil {
		t.Fatalf("unable to broadcast alice spend txn: %v", err)
	}

	// Create the spending script for a p2sh-ified p2pkh output.
	bldr := txscript.NewScriptBuilder()
	bldr.AddData(aliceSig)
	bldr.AddData(alicePub.SerializeCompressed())
	bldr.AddData(toAliceScript)
	aliceSigScript, err := bldr.Script()
	if err != nil {
		t.Fatalf("unable to create alice's spending script: %v", err)
	}

	aliceSpendTx.TxIn[0].SignatureScript = aliceSigScript
	if _, err := rpcClient.SendRawTransaction(aliceSpendTx, true); err != nil {
		t.Fatalf("unable to broadcast alice spend txn to node: %v", err)
	}

	// Mine one block, in order to include alice's spend.
	// 2 more blocks until Bob can spend.
	if _, err := rpcClient.Generate(1); err != nil {
		t.Fatalf("unable to mine block: %v", err)
	}

	// Now craft, sign, and broadcast a spending tx for Bob. At this point,
	// it's been 2 blocks since the commitment tx was included in the chain.
	// Therefore, if Bob attempts a spend, it should be rejected. Since the
	// top stack item will be greater than the masked sequence num.
	bobSpendTx := wire.NewMsgTx()
	bobSpendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *fundTxid,
			Index: 0, // The "pay-to-self" output.
		},
		Sequence: csvTimeout, // Relative time lock of 3 blocks.
	})
	bobSpendTx.AddTxOut(&wire.TxOut{
		Value:    4e8,
		PkScript: aliceOutputScript, // Back to alice ¯\_(ツ)_/¯
	})

	bobRedeemScript, err := commitScriptToSelf(csvTimeout, bobPub,
		alicePub, revokeHash)
	if err != nil {
		t.Fatalf("unable to create bob redeem script: %v", err)
	}

	bobSign := func() {
		bobSig, err := txscript.RawTxInSignature(bobSpendTx, 0,
			bobRedeemScript, txscript.SigHashAll, bobPriv)
		if err != nil {
			t.Fatalf("unable to broadcast bob spend txn: %v", err)
		}

		// Create the spending script for a p2sh-ified p2pkh output.
		bldr := txscript.NewScriptBuilder()
		bldr.AddData(bobSig)
		var empty []byte
		bldr.AddData(empty) // Dummy since we don't have the pre-image
		bldr.AddData(bobRedeemScript)
		bobSigScript, err := bldr.Script()
		if err != nil {
			t.Fatalf("unable to create bob's spending script: %v", err)
		}

		bobSpendTx.TxIn[0].SignatureScript = bobSigScript
	}

	// Bob's tx is first version 1, the spend should be rejected.
	bobSpendTx.Version = 1
	bobSign()
	if _, err := rpcClient.SendRawTransaction(bobSpendTx, true); err == nil {
		t.Fatalf("bob spend should have failed, tx version is 2")
	}

	// Set the proper tx version. For CSV, it must be >= 2.
	bobSpendTx.Version = 2

	// Bob's tx has a mismatched sequence num, should be rejected.
	bobSpendTx.TxIn[0].Sequence = lockTimeToSequence(true, 3) // true=seconds
	bobSign()
	if _, err := rpcClient.SendRawTransaction(bobSpendTx, true); err == nil {
		t.Fatalf("bob spend should have failed, stack has blocks tx has seconds")
	}

	// Bob's tx has the disable flag set on sequence, should be rejected.
	bobSpendTx.TxIn[0].Sequence = lockTimeToSequence(false, 3) | (1 << 31)
	bobSign()
	if _, err := rpcClient.SendRawTransaction(bobSpendTx, true); err == nil {
		t.Fatalf("bob spend should have failed, disable csv is et")
	}

	// Create the final valid transaction for bob. This should still fail
	// since 3 blocks haven't been mined yet.
	bobSpendTx.TxIn[0].Sequence = lockTimeToSequence(false, 3)
	bobSign()
	if _, err := rpcClient.SendRawTransaction(bobSpendTx, true); err == nil {
		t.Fatalf("bob spend should have failed, 3 blocks not mined yet")
	}

	// Mine a second block.
	if _, err := rpcClient.Generate(1); err != nil {
		t.Fatalf("unable to mine block: %v", err)
	}

	// Bob corrects his tx, should now be able to spend his outputs. This
	// transaction should be accepted into the memoool, since it's eligible
	// to get into the next block.
	bobTxid, err := rpcClient.SendRawTransaction(bobSpendTx, true)
	if err != nil {
		t.Fatalf("bob spend should be accepted to mempool: %v", err)
	}

	// Bob's tx should be included in this final block (3rd block since
	// commitment tx hit the chain.)
	blockHash, err := rpcClient.Generate(1)
	if err != nil {
		t.Fatalf("unable to mine block: %v", err)
	}
	block, err := rpcClient.GetBlock(blockHash[0])
	if err != nil {
		t.Fatalf("unable to mine block: %v", err)
	}
	if !bytes.Equal(block.Transactions()[1].Sha().Bytes(),
		bobTxid.Bytes()) {
		t.Fatalf("bob's txn wasn't included in this block: %v",
			block.Transactions)
	}
}
