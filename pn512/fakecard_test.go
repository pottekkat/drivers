package pn512

type fakeClassic struct {
	uid  [4]byte
	sak  uint8
	atqa [2]byte
	mem  [64][16]byte

	keyA [16][6]byte
	keyB [16][6]byte

	halted      bool
	selected    bool
	session     int
	pending     int
	writes      int
	badBCC      bool
	partialATQA bool
}

func newFakeClassic() *fakeClassic {
	c := &fakeClassic{
		uid:     [4]byte{0xD2, 0xB7, 0xFA, 0x06},
		sak:     0x08,
		atqa:    [2]byte{0x04, 0x00},
		session: -1,
		pending: -1,
	}
	// Block 0 as the card reads: UID, BCC, SAK, ATQA, manufacturer bytes.
	c.mem[0] = [16]byte{
		0xD2, 0xB7, 0xFA, 0x06, 0x99, 0x08, 0x04, 0x00,
		0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
	}
	for s := 0; s < 16; s++ {
		c.keyA[s] = DefaultKey
		c.keyB[s] = DefaultKey
		t := s*4 + 3
		copy(c.mem[t][0:6], DefaultKey[:])
		copy(c.mem[t][6:10], []byte{0xFF, 0x07, 0x80, 0x69})
		copy(c.mem[t][10:16], DefaultKey[:])
	}
	return c
}

func (c *fakeClassic) authenticate(keyType KeyType, block uint8, key [6]byte, uid []byte) bool {
	if !c.selected || int(block) >= len(c.mem) {
		return false
	}
	if [4]byte{uid[0], uid[1], uid[2], uid[3]} != c.uid {
		return false
	}
	sector := int(block) / 4
	want := c.keyA[sector]
	if keyType == KeyB {
		want = c.keyB[sector]
	}
	if key != want {
		c.session = -1
		c.selected = false
		return false
	}
	c.session = sector
	c.pending = -1
	return true
}

func (c *fakeClassic) exchange(frame []byte, lastBits uint8, readerCrypto bool) ([]byte, uint8, uint8) {
	if c.session >= 0 && !readerCrypto {
		return nil, 0, 0
	}

	if c.pending >= 0 {
		return c.writeData(frame)
	}

	if len(frame) == 1 && lastBits == 7 {
		return c.request(frame[0])
	}
	if !c.selected {
		return c.anticollision(frame)
	}

	switch frame[0] {
	case piccHLTA:
		if len(frame) != 4 || !crcOK(frame) {
			return nil, 0, errCRC
		}
		c.halted = true
		c.selected = false
		c.session = -1
		return nil, 0, 0

	case piccRead:
		if c.session < 0 {
			return nil, 0, errProtocol
		}
		if len(frame) != 4 || !crcOK(frame) {
			return []byte{mifareNAKTransmission}, 4, 0
		}
		blk := int(frame[1])
		if blk/4 != c.session {
			return []byte{mifareNAKInvalidOp}, 4, 0
		}
		out := make([]byte, 18)
		copy(out, c.readable(blk))
		out[16], out[17] = crcA(out[:16])
		return out, 0, 0

	case piccWrite:
		if c.session < 0 {
			return nil, 0, errProtocol
		}
		if len(frame) != 4 || !crcOK(frame) {
			return []byte{mifareNAKTransmission}, 4, 0
		}
		blk := int(frame[1])
		if blk/4 != c.session || blk == 0 {
			return []byte{mifareNAKInvalidOp}, 4, 0
		}
		c.pending = blk
		return []byte{mifareACK}, 4, 0
	}
	return nil, 0, errProtocol
}

func (c *fakeClassic) readable(blk int) []byte {
	out := make([]byte, 16)
	copy(out, c.mem[blk][:])
	if isTrailer(uint8(blk)) {
		for i := 0; i < 6; i++ {
			out[i] = 0
		}
	}
	return out
}

func (c *fakeClassic) writeData(frame []byte) ([]byte, uint8, uint8) {
	blk := c.pending
	c.pending = -1
	if len(frame) != 18 || !crcOK(frame) {
		return []byte{mifareNAKTransmission}, 4, 0
	}
	copy(c.mem[blk][:], frame[:16])
	if isTrailer(uint8(blk)) {
		sector := blk / 4
		copy(c.keyA[sector][:], frame[0:6])
		copy(c.keyB[sector][:], frame[10:16])
	}
	c.writes++
	return []byte{mifareACK}, 4, 0
}

func (c *fakeClassic) request(cmd uint8) ([]byte, uint8, uint8) {
	if cmd == piccREQA && c.halted {
		return nil, 0, 0
	}
	if cmd != piccREQA && cmd != piccWUPA {
		return nil, 0, errProtocol
	}
	c.halted = false
	c.selected = false
	c.session = -1
	if c.partialATQA {
		return []byte{c.atqa[0], c.atqa[1]}, 4, 0
	}
	return []byte{c.atqa[0], c.atqa[1]}, 0, 0
}

func (c *fakeClassic) anticollision(frame []byte) ([]byte, uint8, uint8) {
	if len(frame) < 2 || frame[0] != piccSelCL1 {
		return nil, 0, errProtocol
	}
	bcc := c.uid[0] ^ c.uid[1] ^ c.uid[2] ^ c.uid[3]
	if c.badBCC {
		bcc ^= 0xFF
	}

	if frame[1] == 0x20 {
		return []byte{c.uid[0], c.uid[1], c.uid[2], c.uid[3], bcc}, 0, 0
	}
	if frame[1] == 0x70 && len(frame) == 9 {
		if !crcOK(frame) {
			return nil, 0, errCRC
		}
		if [4]byte{frame[2], frame[3], frame[4], frame[5]} != c.uid || frame[6] != bcc {
			return nil, 0, 0
		}
		c.selected = true
		out := []byte{c.sak, 0, 0}
		out[1], out[2] = crcA(out[:1])
		return out, 0, 0
	}
	return nil, 0, errProtocol
}

func crcOK(frame []byte) bool {
	if len(frame) < 3 {
		return false
	}
	lo, hi := crcA(frame[:len(frame)-2])
	return lo == frame[len(frame)-2] && hi == frame[len(frame)-1]
}
