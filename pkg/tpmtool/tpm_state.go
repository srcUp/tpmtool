package tpmtool

import (
	"fmt"

	"github.com/systemboot/tpmtool/pkg/tpm"
)

type Pcr struct {
	// PCR index
	index uint8
	// Current Hash
	hash PCRDigestInfo 
	// Event Log
	log PCRLog
}

type PcrBank struct {
	algId
	pcrs [TPMMaxPCRListSize]Pcr
}

type TpmState struct {
}

// 
func (p *Pcr) Calculate() (PCRDigestInfo, error) {
}

// PCRDigestValue is the hash and algorithm
type PCRDigestValue struct {
	DigestAlg IAlgHash
	Digest    []byte
}

// PCRDigestInfo is the info about the measurements
type PCRDigestInfo struct {
	PcrIndex     int
	PcrEventName string
	PcrEventData string
	Digests      []PCRDigestValue
}
func (p *Pcr) Verify() error {
	calculated, err := p.Calculate()
	if err != nil {
		return err
	}

	for _, d := range p.hash.Digests {
		matched := false
		for _, c := range calculated.Digests {
			
}

func (p *Pcr) FindEvent(evType uint32, evData []byte) (*PCRDigestInfo , error) {
}

func (p *Pcr) ReplaceEvent(evType uint32, evData []byte, ev *PCRDigestInfo) error {
}
