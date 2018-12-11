package bip66_test

import (
	"testing"

	"github.com/sammy00/bip66"
)

func TestIsValidSignatureEncoding(t *testing.T) {
	var testCases []*bip66.Goldie
	bip66.ReadGoldenJSON(t, &testCases)

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
