package pn512

import "testing"

func TestCardType(t *testing.T) {
	tests := []struct {
		name string
		atqa [2]byte
		sak  uint8
		want Type
	}{
		{"Classic 1K", [2]byte{0x04, 0x00}, 0x08, TypeClassic1K},
		{"Classic 4K", [2]byte{0x02, 0x00}, 0x18, TypeClassic4K},
		{"Mini", [2]byte{0x04, 0x00}, 0x09, TypeClassicMini},
		{"Ultralight", [2]byte{0x44, 0x00}, 0x00, TypeUltralight},
		{"NTAG213", [2]byte{0x44, 0x00}, 0x00, TypeUltralight},
		{"DESFire", [2]byte{0x44, 0x03}, 0x20, TypeISO14443_4},
		{"14443-4 with other bits", [2]byte{0x04, 0x00}, 0x28, TypeISO14443_4},
		{"quiet card, wrong ATQA", [2]byte{0x04, 0x00}, 0x00, TypeUnknown},
		{"unrecognised SAK", [2]byte{0x04, 0x00}, 0x11, TypeUnknown},
	}

	for _, tt := range tests {
		c := Card{ATQA: tt.atqa, SAK: tt.sak}
		if got := c.Type(); got != tt.want {
			t.Errorf("%s: Type() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCardTypeATQAByteOrder(t *testing.T) {
	swapped := Card{ATQA: [2]byte{0x00, 0x44}, SAK: 0x00}
	if got := swapped.Type(); got == TypeUltralight {
		t.Error("ATQA read in the wrong byte order was accepted as Ultralight")
	}
}

func TestTypeString(t *testing.T) {
	if TypeUnknown.String() != "unknown" {
		t.Errorf("TypeUnknown.String() = %q", TypeUnknown.String())
	}
	for _, ty := range []Type{TypeClassic1K, TypeClassic4K, TypeClassicMini, TypeUltralight, TypeISO14443_4} {
		if ty.String() == "unknown" {
			t.Errorf("Type(%d) has no name", ty)
		}
	}
}
