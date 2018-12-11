package bip66_test

import (
	"flag"
	"testing"

	"github.com/sammy00/bip66"
)

var update = flag.Bool("update", false, "update golden files")

func TestIsValidSignatureEncoding(t *testing.T) {
	if *update {
		UpdateGoldenJSON(t)
	}

	var testCases []*Goldie
	ReadGoldenJSON(t, &testCases)

	for i, c := range testCases {
		// append the dummy sighash flag
		c.Sig = append(c.Sig, 0x00)

		ok := bip66.IsValidSignatureEncoding(c.Sig)

		if ok && !c.OK {
			t.Fatalf("#%d [%s] false positive", i, c.Description)
		} else if !ok && c.OK {
			t.Fatalf("#%d [%s] false negative", i, c.Description)
		}
	}
}
