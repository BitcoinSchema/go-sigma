package sigma

import (
	"strconv"

	"github.com/bitcoinschema/go-bpu"
)

func NewSigFromTape(tape bpu.Tape, vout int) (s *Sig) {
	s = new(Sig)
	s.FromTape(tape, vout)
	return
}

// FromTape takes a BOB Tape and returns an Aip data structure.
// Using the FromTape() alone will prevent validation (data is needed via SetData to enable)
func (s *Sig) FromTape(tape bpu.Tape, vout int) {

	// Not a valid tape?
	if len(tape.Cell) < 4 {
		return
	}

	// Loop to find start of AIP
	var startIndex int
	found := false
	for i, cell := range tape.Cell {
		if *cell.S == Prefix {
			startIndex = i
			found = true
			break
		}
	}

	if !found || len(tape.Cell) < 5 {
		return
	}
	s.TargetVout = vout
	// Set the SIGMA fields
	if tape.Cell[startIndex+1].S != nil {
		s.Algorithm = Algorithm(*tape.Cell[startIndex+1].S)
	}
	if tape.Cell[startIndex+2].S != nil {
		s.Address = *tape.Cell[startIndex+2].S
	}
	if tape.Cell[startIndex+3].B != nil {
		s.Signature = *tape.Cell[startIndex+3].B
	}
	if tape.Cell[startIndex+4].S != nil {
		vin, err := strconv.Atoi(*tape.Cell[startIndex+4].S)
		if err != nil {
			return
		}
		s.Vin = int(vin)
	}
}
