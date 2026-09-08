package pn512

import (
	"errors"
	"testing"
	"time"
)

func newTestDevice(t *testing.T) (*Device, *fakeBus, *fakeClassic) {
	t.Helper()
	card := newFakeClassic()
	bus := newFakeBus(card)
	dev := New(bus)
	if err := dev.Configure(Config{}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return &dev, bus, card
}

// selectCard runs the real anticollision path and returns the UID.
func selectCard(t *testing.T, dev *Device) Card {
	t.Helper()
	card, err := dev.ReadCard()
	if err != nil {
		t.Fatalf("ReadCard: %v", err)
	}
	return card
}

func TestConnectedAcceptsKnownVersions(t *testing.T) {
	tests := []struct {
		name    string
		version uint8
		want    bool
	}{
		{"v1.0", 0x80, true},
		{"v2.0", 0x82, true},
		{"unprogrammed", 0x00, false},
		{"some other part", 0x91, false},
	}
	for _, tt := range tests {
		bus := newFakeBus(nil)
		bus.version = tt.version
		bus.reg[regVersion] = tt.version
		dev := New(bus)
		if got := dev.Connected(); got != tt.want {
			t.Errorf("%s: Connected() with VersionReg %#02x = %v, want %v", tt.name, tt.version, got, tt.want)
		}
	}
}

func TestConfigureDetectsChip(t *testing.T) {
	bus := newFakeBus(nil)
	dev := New(bus)
	if err := dev.Configure(Config{}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if bus.reg[regTxControl]&txRFEn != txRFEn {
		t.Errorf("TxControlReg = %#02x, antenna drivers not enabled", bus.reg[regTxControl])
	}
	if bus.reg[regControl]&0x10 == 0 {
		t.Error("ControlReg Initiator bit not set")
	}
}

func TestConfigureRejectsUnknownChip(t *testing.T) {
	bus := newFakeBus(nil)
	bus.version = 0x91
	bus.softReset()
	dev := New(bus)
	if err := dev.Configure(Config{}); !errors.Is(err, ErrNotDetected) {
		t.Errorf("Configure with unknown version = %v, want ErrNotDetected", err)
	}
}

func TestReadCardEmptyField(t *testing.T) {
	bus := newFakeBus(nil)
	dev := New(bus)
	if err := dev.Configure(Config{}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if _, err := dev.ReadCard(); !errors.Is(err, ErrNoCard) {
		t.Errorf("ReadCard on an empty field = %v, want ErrNoCard", err)
	}
}

func TestReadCardIdentity(t *testing.T) {
	dev, _, _ := newTestDevice(t)
	card := selectCard(t, dev)

	if got := card.Bytes(); len(got) != 4 || got[0] != 0xD2 || got[3] != 0x06 {
		t.Errorf("UID = % X, want D2 B7 FA 06", got)
	}
	if card.SAK != 0x08 || card.ATQA != [2]byte{0x04, 0x00} {
		t.Errorf("SAK %#02x ATQA % X, want 08 and 04 00", card.SAK, card.ATQA)
	}
	if card.Type() != TypeClassic1K {
		t.Errorf("Type() = %v, want TypeClassic1K", card.Type())
	}
}

func TestAuthenticateAndRead(t *testing.T) {
	dev, _, card := newTestDevice(t)
	sel := selectCard(t, dev)

	want := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	card.mem[5] = want

	if err := dev.Authenticate(KeyA, 4, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	got, err := dev.ReadBlock(5)
	if err != nil {
		t.Fatalf("ReadBlock: %v", err)
	}
	if got != want {
		t.Errorf("ReadBlock(5) = % X, want % X", got, want)
	}
}

func TestSessionCoversWholeSector(t *testing.T) {
	dev, _, _ := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(KeyA, 7, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	for _, blk := range []uint8{4, 5, 6, 7} {
		if _, err := dev.ReadBlock(blk); err != nil {
			t.Errorf("ReadBlock(%d) inside the session: %v", blk, err)
		}
	}
	if _, err := dev.ReadBlock(8); !errors.Is(err, ErrNotPermitted) {
		t.Errorf("ReadBlock outside the session = %v, want ErrNotPermitted", err)
	}
}

func TestAuthenticateWrongKey(t *testing.T) {
	dev, bus, _ := newTestDevice(t)
	sel := selectCard(t, dev)

	bad := [6]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	if err := dev.Authenticate(KeyA, 4, bad, sel.Bytes()); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Authenticate with a wrong key = %v, want ErrAuthFailed", err)
	}
	if bus.reg[regStatus2]&status2Crypto1On != 0 {
		t.Error("MFCrypto1On set after a rejected key")
	}
}

func TestRecoveryAfterRejectedKey(t *testing.T) {
	dev, _, _ := newTestDevice(t)
	sel := selectCard(t, dev)

	bad := [6]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	if err := dev.Authenticate(KeyA, 4, bad, sel.Bytes()); err == nil {
		t.Fatal("a key that should not work was accepted")
	}
	again, err := dev.ReadCard()
	if err != nil {
		t.Fatalf("re-select after a rejected key: %v", err)
	}
	if err := dev.Authenticate(KeyB, 4, DefaultKey, again.Bytes()); err != nil {
		t.Errorf("Authenticate after recovery: %v", err)
	}
}

func TestAuthenticateRejectsBadArguments(t *testing.T) {
	dev, _, _ := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(0x62, 4, DefaultKey, sel.Bytes()); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("Authenticate with an invalid key type = %v, want ErrInvalidArgument", err)
	}
	if err := dev.Authenticate(KeyA, 4, DefaultKey, []byte{1, 2}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("Authenticate with a short UID = %v, want ErrInvalidArgument", err)
	}
	if err := dev.Authenticate(KeyA, 4, DefaultKey, make([]byte, 5)); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("Authenticate with a 5-byte UID = %v, want ErrInvalidArgument", err)
	}
}

func TestSectorSwitchWithoutClearing(t *testing.T) {
	dev, _, _ := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(KeyA, 3, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}
	if err := dev.Authenticate(KeyA, 59, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("second Authenticate through the open session: %v", err)
	}
	if _, err := dev.ReadBlock(59); err != nil {
		t.Errorf("ReadBlock after the sector switch: %v", err)
	}
}

func TestClearCryptoBeforeHaltStrandsTheCard(t *testing.T) {
	dev, _, _ := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(KeyA, 3, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := dev.ClearCrypto(); err != nil {
		t.Fatalf("ClearCrypto: %v", err)
	}
	if _, err := dev.ReadCard(); err == nil {
		t.Error("re-selected a card that should have been unreachable")
	}
}

func TestReleaseLeavesTheCardSelectable(t *testing.T) {
	dev, bus, _ := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(KeyA, 3, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := dev.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if bus.reg[regStatus2]&status2Crypto1On != 0 {
		t.Error("Release left MFCrypto1On set")
	}
	if _, err := dev.ReadCard(); err != nil {
		t.Errorf("ReadCard after Release: %v", err)
	}
}

func TestWriteBlockRoundTrip(t *testing.T) {
	dev, _, card := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(KeyA, 4, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	want := [16]byte{0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	if err := dev.WriteBlock(4, want); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}
	if card.writes != 1 {
		t.Errorf("card committed %d writes, want 1", card.writes)
	}
	got, err := dev.ReadBlock(4)
	if err != nil {
		t.Fatalf("ReadBlock: %v", err)
	}
	if got != want {
		t.Errorf("read back % X, want % X", got, want)
	}
}

func TestWriteBlockIsTwoPhases(t *testing.T) {
	dev, bus, _ := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(KeyA, 4, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	before := len(bus.sent)
	if err := dev.WriteBlock(4, [16]byte{}); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}
	frames := bus.sent[before:]
	if len(frames) != 2 {
		t.Fatalf("WriteBlock sent %d frames, want 2", len(frames))
	}
	if len(frames[0]) != 4 || frames[0][0] != piccWrite || frames[0][1] != 4 {
		t.Errorf("command phase = % X, want A0 04 and a CRC", frames[0])
	}
	if len(frames[1]) != 18 {
		t.Errorf("data phase = %d bytes, want 18", len(frames[1]))
	}
}

func TestWriteBlockRefusesProtectedBlocks(t *testing.T) {
	dev, _, card := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(KeyA, 3, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	for _, blk := range []uint8{0, 3, 63} {
		if err := dev.WriteBlock(blk, [16]byte{}); !errors.Is(err, ErrBlockProtected) {
			t.Errorf("WriteBlock(%d) = %v, want ErrBlockProtected", blk, err)
		}
	}
	if card.writes != 0 {
		t.Errorf("card committed %d writes, want 0", card.writes)
	}
}

func TestWriteTrailerRoundTrip(t *testing.T) {
	dev, _, card := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(KeyA, 63, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	access := [4]byte{0xFF, 0x07, 0x80, 0x69}
	newB := [6]byte{1, 2, 3, 4, 5, 6}
	if err := dev.WriteTrailer(15, DefaultKey, access, newB); err != nil {
		t.Fatalf("WriteTrailer: %v", err)
	}
	if card.keyB[15] != newB {
		t.Errorf("card key B = % X, want % X", card.keyB[15], newB)
	}

	got, err := dev.ReadBlock(63)
	if err != nil {
		t.Fatalf("ReadBlock: %v", err)
	}
	for i := 0; i < 6; i++ {
		if got[i] != 0 {
			t.Errorf("trailer byte %d = %#02x, want 00", i, got[i])
		}
	}
	if [4]byte{got[6], got[7], got[8], got[9]} != access {
		t.Errorf("access bytes = % X, want % X", got[6:10], access)
	}
	if [6]byte{got[10], got[11], got[12], got[13], got[14], got[15]} != newB {
		t.Errorf("key B = % X, want % X", got[10:16], newB)
	}
}

func TestWriteTrailerRefusesBadAccessBits(t *testing.T) {
	dev, _, card := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(KeyA, 63, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	bad := [4]byte{0x00, 0x00, 0x00, 0x69}
	if err := dev.WriteTrailer(15, DefaultKey, bad, DefaultKey); !errors.Is(err, ErrBadAccessBits) {
		t.Errorf("WriteTrailer with malformed access bits = %v, want ErrBadAccessBits", err)
	}
	if card.writes != 0 {
		t.Error("a malformed trailer reached the card")
	}
}

func TestBusErrorSurfaces(t *testing.T) {
	bus := newFakeBus(newFakeClassic())
	dev := New(bus)
	if err := dev.Configure(Config{}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	bus.txErr = errorString("bus wedged")
	if _, err := dev.ReadCard(); err == nil {
		t.Error("ReadCard reported success on a dead bus")
	}
}

func TestAuthenticateAfterCardLeavesTheField(t *testing.T) {
	dev, bus, _ := newTestDevice(t)
	sel := selectCard(t, dev)

	if err := dev.Authenticate(KeyA, 4, DefaultKey, sel.Bytes()); err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}

	bus.card = nil
	err := dev.Authenticate(KeyA, 8, DefaultKey, sel.Bytes())
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Authenticate into an empty field = %v, want ErrAuthFailed", err)
	}
	if bus.crypto {
		t.Error("MFCrypto1On still set after a failed authentication")
	}
}

func TestValuesAfterCollIsRestored(t *testing.T) {
	dev, bus, card := newTestDevice(t)

	if _, err := dev.ReadCard(); err != nil {
		t.Fatalf("ReadCard: %v", err)
	}
	if bus.reg[regColl]&collValuesAfterColl == 0 {
		t.Error("ValuesAfterColl clear after a successful select")
	}

	card.badBCC = true
	if _, err := dev.ReadCard(); !errors.Is(err, ErrBCC) {
		t.Fatalf("ReadCard with a bad BCC = %v, want ErrBCC", err)
	}
	if bus.reg[regColl]&collValuesAfterColl == 0 {
		t.Error("ValuesAfterColl clear after a failed anticollision")
	}
}

func TestPartialLastByteIsRejected(t *testing.T) {
	dev, _, card := newTestDevice(t)
	card.partialATQA = true

	if _, err := dev.ReadCard(); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("ReadCard with a partial ATQA = %v, want ErrShortFrame", err)
	}
}

func TestConfigureRejectsTooLongTimeout(t *testing.T) {
	bus := newFakeBus(nil)
	dev := New(bus)
	if err := dev.Configure(Config{Timeout: MaxTimeout + time.Millisecond}); !errors.Is(err, ErrBadTimeout) {
		t.Errorf("Configure past MaxTimeout = %v, want ErrBadTimeout", err)
	}
	if err := dev.Configure(Config{Timeout: MaxTimeout}); err != nil {
		t.Errorf("Configure at MaxTimeout: %v", err)
	}
}
