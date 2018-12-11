package bip66

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type Goldie struct {
	Description string
	Sig         []byte
	OK          bool
}

func (goldie *Goldie) MarshalJSON() ([]byte, error) {
	goldieJSON := map[string]interface{}{
		"description": goldie.Description,
		"signature":   hex.EncodeToString(goldie.Sig),
		"valid":       goldie.OK,
	}

	return json.Marshal(goldieJSON)
}

func (goldie *Goldie) UnmarshalJSON(data []byte) error {
	var goldieJSON map[string]interface{}

	if err := json.Unmarshal(data, &goldieJSON); nil != err {
		return err
	}

	goldie.Description = goldieJSON["description"].(string)
	goldie.Sig, _ = hex.DecodeString(goldieJSON["signature"].(string))
	goldie.OK = goldieJSON["valid"].(bool)

	return nil
}

func ReadGoldenJSON(t *testing.T, golden interface{}) {
	fd, err := os.Open(filepath.Join("testdata", "bip66.json"))
	if nil != err {
		t.Fatal(err)
	}
	defer fd.Close()

	if err := json.NewDecoder(fd).Decode(golden); nil != err {
		t.Fatal(err)
	}
}
