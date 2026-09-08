package pn512

import "testing"

// FF 07 80 is what every sector trailer of an unpersonalised Classic 1K
// contains, read off the card with this driver.
func TestValidateAccessTransport(t *testing.T) {
	cond, err := ValidateAccess(AccessTransport)
	if err != nil {
		t.Fatalf("factory access bytes rejected: %v", err)
	}

	// Factory data blocks are condition 000: read and write with either key.
	want := [4]uint8{0, 0, 0, 1}
	if cond != want {
		t.Errorf("conditions = %v, want %v", cond, want)
	}
}

func TestValidateAccessRejectsInconsistent(t *testing.T) {
	tests := []struct {
		name   string
		access [4]byte
	}{
		// One bit flipped in each byte in turn. Each breaks the inverted copy.
		{"byte 6 corrupt", [4]byte{0xFE, 0x07, 0x80, 0x69}},
		{"byte 7 corrupt", [4]byte{0xFF, 0x06, 0x80, 0x69}},
		{"byte 8 corrupt", [4]byte{0xFF, 0x07, 0x81, 0x69}},
		{"all zeros", [4]byte{0x00, 0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		if _, err := ValidateAccess(tt.access); err != ErrBadAccessBits {
			t.Errorf("%s: err = %v, want ErrBadAccessBits", tt.name, err)
		}
	}
}

// Byte 9 has no meaning to the card, so changing it must not affect validation.
func TestValidateAccessIgnoresUserByte(t *testing.T) {
	a := AccessTransport
	a[3] = 0x00
	if _, err := ValidateAccess(a); err != nil {
		t.Errorf("user byte affected validation: %v", err)
	}
}

func TestValueRoundTrip(t *testing.T) {
	tests := []int32{0, 1, -1, 100, -100, 2147483647, -2147483648}
	for _, want := range tests {
		got, addr, err := DecodeValue(EncodeValue(want, 5))
		if err != nil {
			t.Errorf("value %d: %v", want, err)
			continue
		}
		if got != want {
			t.Errorf("value = %d, want %d", got, want)
		}
		if addr != 5 {
			t.Errorf("addr = %d, want 5", addr)
		}
	}
}

func TestEncodeValueLayout(t *testing.T) {
	got := EncodeValue(1, 5)
	want := [16]byte{
		0x01, 0x00, 0x00, 0x00,
		0xFE, 0xFF, 0xFF, 0xFF,
		0x01, 0x00, 0x00, 0x00,
		0x05, 0xFA, 0x05, 0xFA,
	}
	if got != want {
		t.Errorf("EncodeValue(1, 5) = % X, want % X", got, want)
	}
}

func TestDecodeValueRejectsNonValueBlock(t *testing.T) {
	if _, _, err := DecodeValue([16]byte{}); err != ErrNotValueBlock {
		t.Errorf("all-zero block: err = %v, want ErrNotValueBlock", err)
	}

	for _, i := range []int{0, 4, 8, 12, 13, 14, 15} {
		b := EncodeValue(42, 7)
		b[i] ^= 0xFF
		if _, _, err := DecodeValue(b); err != ErrNotValueBlock {
			t.Errorf("byte %d corrupted: err = %v, want ErrNotValueBlock", i, err)
		}
	}
}

func TestIsTrailer(t *testing.T) {
	// A 1K card, and the first half of a 4K card: four-block sectors.
	for _, b := range []uint8{3, 7, 11, 63, 127} {
		if !isTrailer(b) {
			t.Errorf("block %d should be a trailer", b)
		}
	}
	for _, b := range []uint8{0, 1, 2, 4, 62, 126} {
		if isTrailer(b) {
			t.Errorf("block %d should not be a trailer", b)
		}
	}
	// The upper half of a 4K card has sixteen-block sectors. A plain block%4
	// gets these wrong.
	for _, b := range []uint8{143, 159, 255} {
		if !isTrailer(b) {
			t.Errorf("block %d should be a trailer", b)
		}
	}
	for _, b := range []uint8{128, 131, 142, 144} {
		if isTrailer(b) {
			t.Errorf("block %d should not be a trailer", b)
		}
	}
}

// A transposed trailer does not surface as a failed write. The card accepts
// it and is then locked with keys nobody has, so pin the layout here.
func TestEncodeTrailerLayout(t *testing.T) {
	keyA := [6]byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}
	keyB := [6]byte{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5}

	got := encodeTrailer(keyA, AccessTransport, keyB)
	want := [16]byte{
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
		0xFF, 0x07, 0x80, 0x69,
		0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
	}
	if got != want {
		t.Errorf("encodeTrailer = % X, want % X", got, want)
	}
}

// A factory trailer dumped off the card reads
// 00 00 00 00 00 00 FF 07 80 69 FF FF FF FF FF FF. Key A reads as zeros.
func TestEncodeTrailerMatchesFactoryCard(t *testing.T) {
	got := encodeTrailer(DefaultKey, AccessTransport, DefaultKey)

	onCard := [16]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0x07, 0x80, 0x69,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}
	for i := 6; i < 16; i++ {
		if got[i] != onCard[i] {
			t.Errorf("byte %d = %02X, card holds %02X", i, got[i], onCard[i])
		}
	}
	for i := 0; i < 6; i++ {
		if got[i] != 0xFF {
			t.Errorf("key A byte %d = %02X, want FF", i, got[i])
		}
	}
}

func TestTrailerBlock(t *testing.T) {
	tests := []struct {
		sector uint8
		block  uint8
	}{
		{0, 3}, {1, 7}, {15, 63}, // 1K card
		{31, 127},            // last four-block sector
		{32, 143}, {39, 255}, // the 4K card's sixteen-block sectors
	}
	for _, tt := range tests {
		got, err := trailerBlock(tt.sector)
		if err != nil {
			t.Errorf("sector %d: %v", tt.sector, err)
			continue
		}
		if got != tt.block {
			t.Errorf("sector %d = block %d, want %d", tt.sector, got, tt.block)
		}
		if !isTrailer(got) {
			t.Errorf("sector %d: block %d not recognised as a trailer", tt.sector, got)
		}
	}
	if _, err := trailerBlock(40); err == nil {
		t.Error("sector 40 should be out of range")
	}
}

func TestNackError(t *testing.T) {
	tests := []struct {
		code       uint8
		want       error
		bufferLost bool
	}{
		{0x0A, nil, false},
		{0x00, ErrNotPermitted, false},
		{0x01, ErrTransmission, false},
		{0x04, ErrNotPermitted, true},
		{0x05, ErrTransmission, true},

		{0x02, ErrNACK, false},
		{0x0F, ErrNACK, true},
	}
	for _, tt := range tests {
		if got := nackError(tt.code); got != tt.want {
			t.Errorf("nackError(%#x) = %v, want %v", tt.code, got, tt.want)
		}
		if got := bufferLost(tt.code); got != tt.bufferLost {
			t.Errorf("bufferLost(%#x) = %v, want %v", tt.code, got, tt.bufferLost)
		}
	}
}
