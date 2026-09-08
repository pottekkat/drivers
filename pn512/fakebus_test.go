package pn512

type fakeBus struct {
	reg         [64]uint8
	fifo        []byte
	version     uint8
	card        fakeCard
	crypto      bool
	sent        [][]byte
	authPending bool
	txErr       error
}

type fakeCard interface {
	exchange(frame []byte, lastBits uint8, readerCrypto bool) (reply []byte, replyLastBits uint8, errFlags uint8)

	authenticate(keyType KeyType, block uint8, key [6]byte, uid []byte) bool
}

func newFakeBus(card fakeCard) *fakeBus {
	b := &fakeBus{card: card}
	b.softReset()
	return b
}

func (b *fakeBus) softReset() {
	b.reg = [64]uint8{}
	b.fifo = nil
	b.crypto = false
	b.authPending = false
	b.reg[regCommIRq] = 0x14
	if b.version == 0 {
		b.version = 0x82
	}
	b.reg[regVersion] = b.version
	b.reg[regTxControl] = 0x80
	b.reg[regColl] = 0xA0
	b.reg[regRFCfg] = 0x48
}

func (b *fakeBus) Tx(addr uint16, w, r []byte) error {
	if b.txErr != nil {
		return b.txErr
	}
	if addr != DefaultAddress {
		return errNoDevice
	}
	if len(w) == 0 {
		return errNoDevice
	}
	reg := w[0] & 0x3F

	if len(r) > 0 {
		for i := range r {
			r[i] = b.readReg(reg)
		}
		return nil
	}
	if len(w) == 1 {
		return nil
	}
	for _, v := range w[1:] {
		b.writeReg(reg, v)
	}
	return nil
}

var errNoDevice = errorString("fake: no device at that address")

type errorString string

func (e errorString) Error() string { return string(e) }

func (b *fakeBus) readReg(reg uint8) uint8 {
	switch reg {
	case regFIFOData:
		if len(b.fifo) == 0 {
			return 0
		}
		v := b.fifo[0]
		b.fifo = b.fifo[1:]
		return v
	case regFIFOLevel:
		return uint8(len(b.fifo))
	}
	return b.reg[reg]
}

func (b *fakeBus) writeReg(reg, v uint8) {
	switch reg {
	case regFIFOData:
		b.fifo = append(b.fifo, v)
		return

	case regFIFOLevel:
		if v&0x80 != 0 {
			b.fifo = nil
		}
		return

	case regCommIRq, regDivIRq:
		// Set1 is bit 7: with it clear, the marked bits are cleared rather than set (ref: 8.2.1.5).
		if v&0x80 != 0 {
			b.reg[reg] |= v & 0x7F
		} else {
			b.reg[reg] &^= v & 0x7F
		}
		return

	case regStatus2:
		b.reg[reg] = v
		b.crypto = v&status2Crypto1On != 0
		return

	case regBitFraming:
		b.reg[reg] = v & 0x7F
		if v&0x80 != 0 && b.reg[regCommand]&0x0F == cmdTransceive {
			b.transmit(v & 0x07)
		}
		return

	case regCommand:
		b.reg[reg] = v
		b.command(v & 0x0F)
		return
	}
	b.reg[reg] = v
}

func (b *fakeBus) command(cmd uint8) {
	switch cmd {
	case cmdIdle:
		if b.authPending {
			b.authPending = false
			b.reg[regStatus2] &^= status2Crypto1On
			b.crypto = false
		}
	case cmdSoftReset:
		b.softReset()
	case cmdCalcCRC:
		lo, hi := crcA(b.fifo)
		b.reg[regCRCResultL], b.reg[regCRCResultH] = lo, hi
		b.reg[regDivIRq] |= irqCRC
	case cmdMFAuthent:
		b.authenticate()
	}
}

func (b *fakeBus) transmit(lastBits uint8) {
	frame := append([]byte(nil), b.fifo...)
	b.sent = append(b.sent, frame)
	b.fifo = nil
	b.reg[regError] = 0

	if b.card == nil {
		b.reg[regCommIRq] |= irqTimer | irqTx
		return
	}
	reply, replyLastBits, errFlags := b.card.exchange(frame, lastBits, b.crypto)
	b.reg[regError] = errFlags
	if errFlags != 0 {
		b.reg[regCommIRq] |= irqErr | irqIdle
		return
	}
	if reply == nil {
		b.reg[regCommIRq] |= irqTimer | irqTx
		return
	}
	b.fifo = reply
	b.reg[regControl] = b.reg[regControl]&^0x07 | replyLastBits
	b.reg[regCommIRq] |= irqRx | irqIdle | irqTx
}

func (b *fakeBus) authenticate() {
	frame := append([]byte(nil), b.fifo...)
	b.fifo = nil
	b.reg[regError] = 0

	if b.card == nil {
		b.reg[regCommIRq] |= irqTimer
		b.authPending = true
		return
	}
	b.reg[regCommIRq] |= irqIdle

	fail := func() {
		b.reg[regError] |= errProtocol
		b.reg[regStatus2] &^= status2Crypto1On
		b.crypto = false
	}
	if len(frame) != 12 {
		fail()
		return
	}
	var key [6]byte
	copy(key[:], frame[2:8])
	if !b.card.authenticate(KeyType(frame[0]), frame[1], key, frame[8:12]) {
		fail()
		return
	}
	b.reg[regStatus2] |= status2Crypto1On
	b.crypto = true
}

func crcA(data []byte) (lo, hi uint8) {
	crc := uint16(0x6363)
	for _, v := range data {
		b := v ^ uint8(crc)
		b ^= b << 4
		crc = crc>>8 ^ uint16(b)<<8 ^ uint16(b)<<3 ^ uint16(b)>>4
	}
	return uint8(crc), uint8(crc >> 8)
}
