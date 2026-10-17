package system

import (
	"reflect"
	"testing"
)

func TestUnknownParameters(t *testing.T) {
	out := "Load smb config files from /tmp/x\nUnknown parameter encountered: \"pathh\"\nIgnoring unknown parameter \"pathh\"\nUnknown parameter encountered: \"wrteable\"\nLoaded services file OK.\n"
	if got := unknownParameters(out); !reflect.DeepEqual(got, []string{`"pathh"`, `"wrteable"`}) {
		t.Fatalf("got %v", got)
	}
	if got := unknownParameters("Loaded services file OK.\n"); got != nil {
		t.Fatalf("clean output reported %v", got)
	}
}
