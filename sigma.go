package sigma

import (
	"encoding/binary"
	"fmt"
	"strconv"

	bsm "github.com/bitcoin-sv/go-sdk/compat/bsm"
	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	hash "github.com/bitcoin-sv/go-sdk/primitives/hash"
	"github.com/bitcoin-sv/go-sdk/script"
	"github.com/bitcoin-sv/go-sdk/transaction"
	"github.com/bitcoin-sv/go-sdk/util"
)

type Algorithm string

const Prefix = "SIGMA"

// const sigmaHex = "5349474d41"
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
	Signature  []byte
	Algorithm  Algorithm
	Vin        int
	TargetVout int
}

type SignResponse struct {
	Sig
	SigmaScript *script.Script
	SignedTx    *transaction.Transaction
}

type Sigma struct {
	inputHash     []byte
	dataHash      []byte
	transaction   *transaction.Transaction
	sigmaInstance int
	refVin        int
	targetVout    int
	sig           Sig
}

func NewSigma(transaction transaction.Transaction, targetVout, sigmaInstance, refVin int) *Sigma {
	return &Sigma{
		transaction:   &transaction,
		targetVout:    targetVout,
		sigmaInstance: sigmaInstance,
		refVin:        refVin,
	}
}

func (s *Sigma) SetHashes() {
	s.inputHash = s.GetInputHash()
	s.dataHash = s.getDataHash()
}

func (s *Sigma) SetTargetVout(targetVout int) {
	s.targetVout = targetVout
}

func (s *Sigma) SetSigmaInstance(sigmaInstance int) {
	s.sigmaInstance = sigmaInstance
}

func (s *Sigma) GetMessageHash() []byte {
	combinedBytes := append(s.inputHash, s.dataHash...)
	return hash.Sha256d(combinedBytes)
}

func (s *Sigma) Sign(privateKey *ec.PrivateKey) *SignResponse {

	// Get the message hash to sign
	s.SetHashes()
	messageHash := s.GetMessageHash()

	signature, err := bsm.SignMessage(privateKey, messageHash)
	if err != nil {
		fmt.Printf("error signing message: %v\n", err)
		return nil
	}

	// Get the address from the public key
	add, err := script.NewAddressFromPublicKey(privateKey.PubKey(), true)
	if err != nil {
		fmt.Printf("error getting address from public key: %v\n", err)
		return nil
	}

	vin := s.refVin
	if vin == -1 {
		vin = s.targetVout
	}

	output := s.transaction.Outputs[s.targetVout]
	hasOpReturn := false
	for pos := 0; pos < len(*output.LockingScript); {
		if op, err := output.LockingScript.ReadOp(&pos); err != nil {
			fmt.Printf("error reading op: %v\n", err)
			return nil
		} else if op.Op == script.OpRETURN {
			hasOpReturn = true
			break
		}
	}

	if hasOpReturn {
		output.LockingScript.AppendPushData([]byte{'|'})
	} else {
		output.LockingScript.AppendOpcodes(script.OpRETURN)
	}
	output.LockingScript.AppendPushData([]byte(Prefix))
	output.LockingScript.AppendPushData([]byte(BSM))
	output.LockingScript.AppendPushData([]byte(add.AddressString))
	output.LockingScript.AppendPushData(signature)
	output.LockingScript.AppendPushData([]byte(strconv.Itoa(vin)))

	s.sig = Sig{
		Algorithm:  BSM,
		Address:    add.AddressString,
		Signature:  signature,
		Vin:        vin,
		TargetVout: s.targetVout,
	}
	return &SignResponse{
		SigmaScript: output.LockingScript,
		SignedTx:    s.transaction,
		Sig:         s.sig,
	}
}

func (s *Sigma) RemoteSign(keyHost string, authToken *AuthToken) (SignResponse, error) {
	// implementation needed
	return SignResponse{}, nil
}

// GetSig gets the target instance and returns its values
func (s *Sigma) GetSig(scr *script.Script) (*Sig, error) {
	occurrences := 0
	for pos := 0; pos < len(*scr); {
		if op, err := scr.ReadOp(&pos); err != nil {
			return nil, err
		} else if op.Op == script.OpRETURN || (op.Op == script.OpDATA1 && op.Data[0] == '|') {
			if op, err = scr.ReadOp(&pos); err != nil {
				return nil, err
			}
			if op.Op == script.OpDATA5 && string(op.Data) == Prefix {
				if occurrences == s.sigmaInstance {
					if algoOp, err := scr.ReadOp(&pos); err != nil {
						return nil, err
					} else if addOp, err := scr.ReadOp(&pos); err != nil {
						return nil, err
					} else if sigOp, err := scr.ReadOp(&pos); err != nil {
						return nil, err
					} else if vinOp, err := scr.ReadOp(&pos); err != nil {
						return nil, err
					} else if vin, err := strconv.Atoi(string(vinOp.Data)); err != nil {
						return nil, err
					} else {
						return &Sig{
							Algorithm: Algorithm(string(algoOp.Data)),
							Address:   string(addOp.Data),
							Signature: sigOp.Data,
							Vin:       vin,
						}, nil
					}
				}
				occurrences++
			}
		}
	}

	return nil, fmt.Errorf("no signature found")
}

func (s *Sigma) Verify() bool {
	script := s.transaction.Outputs[s.targetVout].LockingScript
	sig, err := s.GetSig(script)

	if err != nil {
		fmt.Println("Error parsing script:", err)
		return false
	}

	s.sig = *sig

	err = bsm.VerifyMessage(s.sig.Address, s.sig.Signature, s.GetMessageHash())
	if err != nil {
		fmt.Printf("Error verifying signature: %v\n", err)
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
		binary.LittleEndian.PutUint32(indexBytes, uint32(txIn.SourceTxOutIndex))
		outpointBytes := append(util.ReverseBytes(txIn.SourceTXID.CloneBytes()), indexBytes...)
		return hash.Sha256(outpointBytes)
	}
	// return dummy hash or handle error
	return hash.Sha256(make([]byte, 32))
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

	occurrences := 0
	prevPos := 0
	for pos := 0; pos < len(*output.LockingScript); {
		op, err := output.LockingScript.ReadOp(&pos)
		if err != nil {
			break
		}

		if op.Op == script.OpRETURN || (op.Op == script.OpDATA1 && op.Data[0] == '|') {
			if op, err := output.LockingScript.ReadOp(&pos); err != nil {
				break
			} else if op.Op == script.OpDATA5 && string(op.Data) == Prefix {
				if occurrences == s.sigmaInstance {
					// The -1 accounts for either the OP_RETURN or "|" separator which is not signed
					return hash.Sha256((*output.LockingScript)[:prevPos])
				}
				occurrences++
			}
		}
		prevPos = pos
	}

	// If no endIndex found, return the hash for the entire script
	return hash.Sha256(*output.LockingScript)
}

func (s *Sigma) getTargetTxOut() *transaction.TransactionOutput {
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

	count := 0
	if scriptChunks, err := script.DecodeScript(*output.LockingScript); err == nil {
		for _, chunk := range scriptChunks {
			if chunk.Op == script.OpDATA5 && string(chunk.Data) == Prefix {
				count++
			}
		}
	}

	return count
}
