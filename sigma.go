package sigma

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/bitcoinschema/go-bitcoin/v2"
	"github.com/libsv/go-bk/bec"
	"github.com/libsv/go-bk/crypto"
	"github.com/libsv/go-bt/v2"
	"github.com/libsv/go-bt/v2/bscript"
)

type Algorithm string

const sigmaHex = "5349474d41"
const (
	BSM Algorithm = "BSM"
)

type AuthToken struct {
	Type  string
	Value string
	Key   string
}

type RemoteSigningResponse struct {
	Address string
	Sig     string
	Message string
	Ts      int
}

type Sig struct {
	Address    string
	Signature  string
	Algorithm  Algorithm
	Vin        int
	TargetVout int
}

type SignResponse struct {
	Sig
	SigmaScript bscript.Script
	SignedTx    bt.Tx
}

type Sigma struct {
	inputHash     string
	dataHash      string
	transaction   *bt.Tx
	sigmaInstance int
	refVin        int
	targetVout    int
	sig           Sig
}

func NewSigma(transaction bt.Tx, targetVout, sigmaInstance, refVin int) *Sigma {
	return &Sigma{
		transaction:   &transaction,
		targetVout:    targetVout,
		sigmaInstance: sigmaInstance,
		refVin:        refVin,
	}
}

func (s *Sigma) SetHashes() {
	s.inputHash = string(s.GetInputHash())
	s.dataHash = string(s.getDataHash())
}

func (s *Sigma) SetTargetVout(targetVout int) {
	s.targetVout = targetVout
}

func (s *Sigma) SetSigmaInstance(sigmaInstance int) {
	s.sigmaInstance = sigmaInstance
}

func (s *Sigma) GetMessageHash() []byte {
	combinedBytes := append([]byte(s.inputHash), []byte(s.dataHash)...)
	return crypto.Sha256d(combinedBytes)
}

func (s *Sigma) Sign(privateKey *bec.PrivateKey) SignResponse {

	// Get the message hash to sign
	messageHash := s.GetMessageHash()

	// Create a signer with the private key
	pkBytes := privateKey.Serialise()
	pkHex := hex.EncodeToString(pkBytes)
	signature, err := bitcoin.SignMessage(pkHex, string(messageHash), false)
	if err != nil {
		fmt.Printf("error signing message: %v\n", err)
		return SignResponse{}
	}

	// Get the address from the public key
	address, err := bitcoin.GetAddressFromPubKey(privateKey.PubKey(), true)
	if err != nil {
		fmt.Printf("error getting address from public key: %v\n", err)
		return SignResponse{}
	}

	vin := s.refVin
	if vin == -1 {
		vin = s.targetVout
	}

	signedAsm := fmt.Sprintf(
		"%s %x %x %s %x",
		sigmaHex,
		[]byte(BSM),
		[]byte(address.AddressString),
		signature,
		[]byte(strconv.Itoa(vin)),
	)

	sigmaScript, err := bscript.NewFromASM(signedAsm)
	if err != nil {
		fmt.Printf("error creating script: %v\n", err)
		return SignResponse{}
	}

	existingAsm := s.getTargetTxOut().LockingScript.String()
	containsOpReturn := strings.Contains(existingAsm, "OP_RETURN")
	separator := "OP_RETURN"
	if containsOpReturn {
		separator = "7c"
	}

	newScriptAsm := fmt.Sprintf("%s %s %s", existingAsm, separator, signedAsm)

	newScript, err := bscript.NewFromASM(newScriptAsm)
	if err != nil {
		fmt.Printf("error creating script: %v\n", err)
		return SignResponse{}
	}

	signedTx := *s.transaction // Assumes transaction is a pointer, adjust as necessary
	signedTxOut := &bt.Output{
		Satoshis:      s.getTargetTxOut().Satoshis,
		LockingScript: newScript,
	}
	signedTx.Outputs[s.targetVout] = signedTxOut

	s.transaction = &signedTx

	return SignResponse{
		SigmaScript: *sigmaScript,
		SignedTx:    signedTx,
		Sig: Sig{
			Algorithm:  BSM,
			Address:    address.AddressString,
			Signature:  base64.StdEncoding.EncodeToString([]byte(signature)),
			Vin:        vin,
			TargetVout: s.targetVout,
		},
	}
}

func (s *Sigma) RemoteSign(keyHost string, authToken *AuthToken) (SignResponse, error) {
	// implementation needed
	return SignResponse{}, nil
}

func (s *Sigma) Verify() bool {
	if s.sig.Signature == "" || s.sig.Address == "" {
		fmt.Println("signature or address is missing")
		return false
	}

	// Ensure the signature and message hash are in the correct format for VerifyMessage
	signatureStr := s.sig.Signature
	messageHashStr := base64.StdEncoding.EncodeToString(s.GetMessageHash())

	err := bitcoin.VerifyMessage(s.sig.Address, signatureStr, messageHashStr)
	if err != nil {
		fmt.Printf("error verifying signature: %v\n", err)
		return false
	}

	return true
}

func (s *Sigma) GetInputHash() []byte {
	vin := s.refVin
	if vin == -1 {
		vin = s.targetVout
	}
	txIn := s.transaction.Inputs[vin]
	if txIn != nil {
		indexBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(indexBytes, uint32(txIn.PreviousTxOutIndex))
		outpointBytes := append(txIn.PreviousTxID(), indexBytes...)
		return crypto.Sha256(outpointBytes)
	}
	// return dummy hash or handle error
	return crypto.Sha256(make([]byte, 32))
}

func (s *Sigma) getDataHash() []byte {
	if s.transaction == nil {
		fmt.Println("error getting transaction")
		return nil
	}

	output := s.getTargetTxOut()
	if output == nil {
		fmt.Println("error getting target tx out")
		return nil
	}

	script := output.LockingScript
	scriptChunks := strings.Split(script.String(), " ")

	// Define sigmaHex as a constant or variable if it's not already defined
	// const sigmaHex = "5349474d41"

	occurrences := 0
	for i, chunk := range scriptChunks {
		if strings.ToUpper(chunk) == sigmaHex {
			if occurrences == s.sigmaInstance {
				// The -1 accounts for either the OP_RETURN
				// or "|" separator which is not signed
				dataChunks := scriptChunks[:i-1]
				dataScript, err := bscript.NewFromASM(strings.Join(dataChunks, " "))
				if err != nil {
					fmt.Printf("error creating script: %v\n", err)
					return nil
				}
				scriptString := dataScript.String()
				scriptBytes, err := hex.DecodeString(scriptString)
				if err != nil {
					fmt.Printf("error decoding script: %v\n", err)
					return nil
				}
				return crypto.Sha256(scriptBytes)
			}
			occurrences++
		}
	}

	// If no endIndex found, return the hash for the entire script
	dataScript, err := bscript.NewFromASM(strings.Join(scriptChunks, " "))
	if err != nil {
		fmt.Printf("error creating script: %v\n", err)
		return nil
	}
	scriptString := dataScript.String()
	scriptBytes, err := hex.DecodeString(scriptString)
	if err != nil {
		fmt.Printf("error decoding script: %v\n", err)
		return nil
	}
	return crypto.Sha256(scriptBytes)
}

func (s *Sigma) getTargetTxOut() *bt.Output {
	if s.transaction == nil {
		return nil
	}
	return s.transaction.Outputs[s.targetVout]
}

func (s *Sigma) GetSigInstanceCount() int {
	output := s.getTargetTxOut()
	if output == nil {
		// handle error or return 0 if appropriate
		return 0
	}

	script := output.LockingScript
	scriptChunks := strings.Split(script.String(), " ")

	count := 0
	for _, chunk := range scriptChunks {
		if strings.ToUpper(chunk) == sigmaHex {
			count++
		}
	}

	return count
}

func (s *Sigma) GetSigInstancePosition() int {
	output := s.getTargetTxOut()
	if output == nil {
		fmt.Println("error getting target tx out")
		return -1
	}

	script := output.LockingScript
	scriptChunks := strings.Split(script.String(), " ")

	for i, chunk := range scriptChunks {
		if strings.ToUpper(chunk) == sigmaHex {
			return i
		}
	}
	fmt.Println("error getting sig instance position")
	return -1 // Return -1 if sigmaHex is not found
}
