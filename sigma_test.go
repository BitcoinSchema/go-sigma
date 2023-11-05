package sigma

import (
	"encoding/hex"
	"testing"

	"github.com/bitcoinschema/go-bitcoin/v2"
	"github.com/libsv/go-bt/v2"
	"github.com/libsv/go-bt/v2/bscript"
	"github.com/stretchr/testify/assert"
)

func setupTx() *bt.Tx {
	// Adjust this setup to match your TypeScript test setup
	outputScriptAsm := "OP_0 OP_RETURN " + hex.EncodeToString([]byte("pushdata1")) + " " + hex.EncodeToString([]byte("pushdata2"))
	script, _ := bscript.NewFromASM(outputScriptAsm)
	tx := bt.NewTx()
	tx.AddOutput(&bt.Output{
		Satoshis:      0,
		LockingScript: script,
	})

	// we must add an input
	tx.Inputs = append(tx.Inputs, (&bt.Input{
		PreviousTxSatoshis: 0,
		PreviousTxScript:   script,
		PreviousTxOutIndex: 0,
		SequenceNumber:     0,
		UnlockingScript:    &bscript.Script{},
	}))

	return tx
}

func TestSigma(t *testing.T) {
	// ... Your other setup code ...

	tx := setupTx()

	t.Run("signs and verifies a message correctly", func(t *testing.T) {
		sigma := NewSigma(*tx, 0, 0, -1)
		pk, err := bitcoin.CreatePrivateKey()
		assert.Nil(t, err)

		signResp := sigma.Sign(pk)
		assert.NotNil(t, signResp.SigmaScript)
		assert.Equal(t, "your-test-signature", signResp.Signature)
		isValid := sigma.Verify()
		assert.True(t, isValid)
	})

	// ... Your other test cases ...
}

// func TestGenerateOutputScript(t *testing.T) {
// 	// ... Your setup code ...

// 	tx := setupTx()

// 	t.Run("generates a correct output script", func(t *testing.T) {
// 		sigma := NewSigma(*tx, 0, 0, -1)
// 		out := sigma.getTargetTxOut()
// 		assert.NotNil(t, out)
// 		asm := out.LockingScript.String()
// 		signResp := sigma.Sign("your-test-signature", "your-test-address")
// 		assert.NotNil(t, signResp.SignedTx)
// 		signedTxOut := signResp.SignedTx.Outputs[0]
// 		assert.NotNil(t, signedTxOut)
// 		asmAfter := signedTxOut.LockingScript.String()
// 		assert.NotEqual(t, asm, asmAfter)
// 	})

// 	// ... Your other test cases ...
// }

// // ... Your other test functions ...
