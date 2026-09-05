package timestamp

import "testing"

func TestCheckDERAcceptsRealTokens(t *testing.T) {
	for i, seed := range seedTokens(t) {
		if err := checkDER(seed); err != nil {
			t.Errorf("seed %d rejected: %v", i, err)
		}
	}
}

func TestCheckDERRejectsMalformedInput(t *testing.T) {
	cases := map[string][]byte{
		"empty":                     {},
		"truncated after tag":       {0x30},
		"fuzz crash input 3f 30":    {0x3f, 0x30},
		"indefinite length":         {0x30, 0x80, 0x00, 0x00},
		"length overruns buffer":    {0x30, 0x05, 0x02, 0x01, 0x00},
		"child overruns parent":     {0x30, 0x03, 0x04, 0x05, 0x00},
		"trailing garbage":          {0x30, 0x00, 0xff},
		"non-minimal length":        {0x30, 0x81, 0x01, 0x00},
		"five length bytes":         {0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
		"high tag number truncated": {0x3f, 0xff},
	}
	for name, input := range cases {
		if err := checkDER(input); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestParseTSRDoesNotPanicOnFuzzCrashInput(t *testing.T) {
	if _, err := parseTSR([]byte{0x3f, 0x30}); err == nil {
		t.Fatal("expected an error, got a parsed token")
	}
}
