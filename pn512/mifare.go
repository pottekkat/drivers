package pn512

import (
	"runtime"
	"time"
)

// ref: NXP MF1S50YYX_V1 datasheet (Rev. 3.2 - 23 May 2018, 279232)
// https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf

// KeyType selects which of a sector's two keys an authentication offers.
type KeyType uint8

const (
	KeyA KeyType = 0x60
	KeyB KeyType = 0x61
)

// DefaultKey is the key a Classic card ships with on every sector.
var DefaultKey = [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

// Two timeouts every MIFARE command runs under.
const (
	// commandTime covers every command phase except the EEPROM commits.
	commandTime = 5 * time.Millisecond

	// programTime covers the phases that commit to EEPROM.
	programTime = 20 * time.Millisecond
)

// Authenticate opens a CRYPTO1 session on the sector holding block. The session
// lasts until the card is halted or leaves the field, so call Release when
// finished. Pass the whole UID. A 7-byte UID authenticates with its last four
// bytes, and this picks them.
//
// Call Authenticate again to switch sectors. Clearing the crypto unit in
// between breaks the next authentication.
func (d *Device) Authenticate(keyType KeyType, block uint8, key [6]byte, uid []byte) error {
	if len(uid) != 4 && len(uid) != 7 {
		return ErrInvalidArgument
	}
	if keyType != KeyA && keyType != KeyB {
		return ErrInvalidArgument
	}

	return d.timed(commandTime, func() error {
		return d.authenticate(keyType, block, key, uid)
	})
}

func (d *Device) authenticate(keyType KeyType, block uint8, key [6]byte, uid []byte) error {
	// Command code, block address, six key bytes, four UID bytes (ref: PN512 rev 5.3, 18.3.1.10).
	var frame [12]byte
	frame[0] = uint8(keyType)
	frame[1] = block
	copy(frame[2:8], key[:])
	copy(frame[8:12], uid[len(uid)-4:])

	d.diag = Diag{}

	if err := d.writeReg(regCommand, cmdIdle); err != nil {
		return err
	}
	if err := d.writeReg(regCommIRq, 0x7F); err != nil {
		return err
	}
	if err := d.writeReg(regBitFraming, 0x00); err != nil {
		return err
	}
	if err := d.writeReg(regFIFOLevel, 0x80); err != nil {
		return err
	}
	if err := d.writeFIFO(frame[:]); err != nil {
		return err
	}
	if err := d.writeReg(regCommand, cmdMFAuthent); err != nil {
		return err
	}

	deadline := time.Now().Add(d.timeout + 100*time.Millisecond)
	var irq uint8
	done := false
	for time.Now().Before(deadline) {
		var err error
		if irq, err = d.readReg(regCommIRq); err != nil {
			return err
		}
		if irq&(irqIdle|irqTimer) != 0 {
			done = true
			break
		}
		runtime.Gosched()
	}
	d.diag.IRQ = irq

	if err := d.writeReg(regCommand, cmdIdle); err != nil {
		return err
	}

	if !done {
		return ErrTimeout
	}

	errReg, err := d.readReg(regError)
	if err != nil {
		return err
	}
	d.diag.Error = errReg

	st2, err := d.readReg(regStatus2)
	if err != nil {
		return err
	}
	d.diag.Status2 = st2
	if st2&status2Crypto1On == 0 {
		return ErrAuthFailed
	}
	return nil
}

// ClearCrypto switches the reader's CRYPTO1 unit off.
func (d *Device) ClearCrypto() error {
	return d.clearBits(regStatus2, status2Crypto1On)
}

// Release halts the card and then switches the reader's crypto unit off.
func (d *Device) Release() error {
	haltErr := d.Halt()
	clearErr := d.ClearCrypto()
	if haltErr != nil {
		return haltErr
	}
	return clearErr
}

// ReadBlock returns the 16 bytes of one block.
func (d *Device) ReadBlock(block uint8) ([16]byte, error) {
	var out [16]byte

	var frame [4]byte
	frame[0] = piccRead
	frame[1] = block
	lo, hi, err := d.crc(frame[:2])
	if err != nil {
		return out, err
	}
	frame[2], frame[3] = lo, hi

	// 16 data bytes plus a two-byte CRC_A.
	buf := d.fifo[:18]
	var n int
	var lastBits uint8
	err = d.timed(commandTime, func() error {
		var e error
		n, lastBits, e = d.transceive(frame[:], 0, buf, 0)
		return e
	})
	if err != nil {
		return out, err
	}
	// A card that refuses the read answers with four bits.
	if n == 1 && lastBits == 4 {
		d.diag.NAK = buf[0] & 0x0F
		if err := nackError(buf[0] & 0x0F); err != nil {
			return out, err
		}
		return out, ErrShortFrame
	}
	if n != 18 {
		return out, ErrShortFrame
	}
	if lo, hi, err = d.crc(buf[0:16]); err != nil {
		return out, err
	}
	if lo != buf[16] || hi != buf[17] {
		return out, ErrCRC
	}
	copy(out[:], buf[0:16])
	return out, nil
}

// WriteBlock replaces the 16 bytes of one block.
func (d *Device) WriteBlock(block uint8, data [16]byte) error {
	// Manufacturer block, read-only.
	if block == 0 {
		return ErrBlockProtected
	}
	// Sector trailers hold the keys.
	if isTrailer(block) {
		return ErrBlockProtected
	}
	return d.writeBlock(block, data)
}

func (d *Device) writeBlock(block uint8, data [16]byte) error {
	err := d.timed(commandTime, func() error {
		return d.mifareCommand(piccWrite, block)
	})
	if err != nil {
		return err
	}
	return d.mifareData(data[:])
}

func isTrailer(block uint8) bool {
	if block < 128 {
		return block%4 == 3
	}
	return block%16 == 15
}

// mifareCommand sends a two-byte MIFARE command and waits for the card's acknowledgement.
func (d *Device) mifareCommand(cmd, arg uint8) error {
	var frame [4]byte
	frame[0] = cmd
	frame[1] = arg
	lo, hi, err := d.crc(frame[:2])
	if err != nil {
		return err
	}
	frame[2], frame[3] = lo, hi
	return d.exchangeACK(frame[:])
}

// dataFrame builds a data phase frame in the FIFO buffer with its CRC_A.
func (d *Device) dataFrame(data []byte) ([]byte, error) {
	buf := d.fifo[:len(data)+2]
	copy(buf, data)
	lo, hi, err := d.crc(data)
	if err != nil {
		return nil, err
	}
	buf[len(data)], buf[len(data)+1] = lo, hi
	return buf, nil
}

// mifareData sends a data phase and waits for its acknowledgement.
func (d *Device) mifareData(data []byte) error {
	buf, err := d.dataFrame(data)
	if err != nil {
		return err
	}
	return d.timed(programTime, func() error { return d.exchangeACK(buf) })
}

// timed runs a function with the chip's countdown timer set to t.
func (d *Device) timed(t time.Duration, fn func() error) error {
	saved := d.timeout
	if err := d.setTimeout(t); err != nil {
		return err
	}
	opErr := fn()

	if err := d.setTimeout(saved); err != nil {
		return err
	}
	return opErr
}

// exchangeACK sends a frame and requires a 4-bit ACK back.
func (d *Device) exchangeACK(frame []byte) error {
	var reply [1]byte
	n, lastBits, err := d.transceive(frame, 0, reply[:], 0)
	if err != nil {
		return err
	}
	if n != 1 || lastBits != 4 {
		return ErrShortFrame
	}
	code := reply[0] & 0x0F
	d.diag.NAK = code
	return nackError(code)
}

// nackError names the card's four-bit answer.
func nackError(code uint8) error {
	if code == mifareACK {
		return nil
	}
	switch code &^ mifareNAKBufferLost {
	case mifareNAKInvalidOp:
		return ErrNotPermitted
	case mifareNAKTransmission:
		return ErrTransmission
	}
	return ErrNACK
}

// bufferLost reports whether a four-bit answer invalidated the card's transfer buffer.
func bufferLost(code uint8) bool {
	return code != mifareACK && code&mifareNAKBufferLost != 0
}

// EncodeValue builds the 16 bytes of a value block.
func EncodeValue(value int32, addr uint8) [16]byte {
	var b [16]byte
	u := uint32(value)
	for i := range 4 {
		v := uint8(u >> (8 * uint(i)))
		b[i] = v
		b[4+i] = ^v
		b[8+i] = v
	}
	b[12], b[13], b[14], b[15] = addr, ^addr, addr, ^addr
	return b
}

// DecodeValue reads a value block back.
func DecodeValue(b [16]byte) (value int32, addr uint8, err error) {
	for i := 0; i < 4; i++ {
		if b[i] != b[8+i] || b[i] != ^b[4+i] {
			return 0, 0, ErrNotValueBlock
		}
	}
	if b[12] != b[14] || b[13] != b[15] || b[12] != ^b[13] {
		return 0, 0, ErrNotValueBlock
	}
	u := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	return int32(u), b[12], nil
}

// WriteValue formats a block as a value block holding value. The address byte
// is set to the block's own number.
func (d *Device) WriteValue(block uint8, value int32) error {
	return d.WriteBlock(block, EncodeValue(value, block))
}

// ReadValue reads a block and decodes it as a value block.
func (d *Device) ReadValue(block uint8) (int32, uint8, error) {
	b, err := d.ReadBlock(block)
	if err != nil {
		return 0, 0, err
	}
	return DecodeValue(b)
}

// IncrementValue adds delta to a value block and leaves the result in the
// card's transfer buffer. The block itself only changes once TransferValue
// writes the buffer back.
func (d *Device) IncrementValue(block uint8, delta int32) error {
	return d.valueOp(piccIncrement, block, delta)
}

// DecrementValue subtracts delta from a value block and leaves the result in
// the card's transfer buffer. The block itself only changes once TransferValue
// writes the buffer back.
func (d *Device) DecrementValue(block uint8, delta int32) error {
	return d.valueOp(piccDecrement, block, delta)
}

// RestoreValue loads a value block into the transfer buffer unchanged, so a
// following TransferValue can copy it to another block in the same sector.
func (d *Device) RestoreValue(block uint8) error {
	return d.valueOp(piccRestore, block, 0)
}

// TransferValue writes the card's transfer buffer to a block.
func (d *Device) TransferValue(block uint8) error {
	return d.timed(programTime, func() error {
		return d.mifareCommand(piccTransfer, block)
	})
}

// valueOp runs the two phases shared by IncrementValue, DecrementValue and
// RestoreValue: the command and block address, then a four-byte little-endian
// operand.
func (d *Device) valueOp(cmd, block uint8, operand int32) error {
	err := d.timed(commandTime, func() error {
		return d.mifareCommand(cmd, block)
	})
	if err != nil {
		return err
	}

	u := uint32(operand)
	var arg [4]byte
	arg[0] = uint8(u)
	arg[1] = uint8(u >> 8)
	arg[2] = uint8(u >> 16)
	arg[3] = uint8(u >> 24)

	buf, err := d.dataFrame(arg[:])
	if err != nil {
		return err
	}

	err = d.timed(programTime, func() error { return d.exchangeACK(buf) })
	if err == ErrNoCard {
		// Part 2 of these three commands is not acknowledged, so silence is
		// the success case and only an explicit NACK is a failure (ref: 12.4).
		return nil
	}
	return err
}

// AccessTransport is the access configuration a Classic card ships with.
var AccessTransport = [4]byte{0xFF, 0x07, 0x80, 0x69}

// ValidateAccess reports whether the first three bytes of an access field are
// self-consistent, and returns the four per-block conditions as C1<<2|C2<<1|C3.
// The fourth byte is the user byte and is not checked, because the card
// assigns it no meaning.
func ValidateAccess(access [4]byte) (cond [4]uint8, err error) {
	b6, b7, b8 := access[0], access[1], access[2]

	c1 := (b7 >> 4) & 0x0F
	c2 := b8 & 0x0F
	c3 := (b8 >> 4) & 0x0F

	// Each condition also appears inverted, in the other half of the field.
	if b6&0x0F != ^c1&0x0F {
		return cond, ErrBadAccessBits
	}
	if (b6>>4)&0x0F != ^c2&0x0F {
		return cond, ErrBadAccessBits
	}
	if b7&0x0F != ^c3&0x0F {
		return cond, ErrBadAccessBits
	}

	for i := range uint8(4) {
		cond[i] = (c1>>i&1)<<2 | (c2>>i&1)<<1 | (c3 >> i & 1)
	}
	return cond, nil
}

// WriteTrailer replaces a sector's keys and access bits. sector is a sector
// number. The session must already be open on that sector with a key its
// access bits permit.
func (d *Device) WriteTrailer(sector uint8, keyA [6]byte, access [4]byte, keyB [6]byte) error {
	if _, err := ValidateAccess(access); err != nil {
		return err
	}
	block, err := trailerBlock(sector)
	if err != nil {
		return err
	}

	return d.writeBlock(block, encodeTrailer(keyA, access, keyB))
}

// encodeTrailer builds the sixteen bytes of a sector trailer.
func encodeTrailer(keyA [6]byte, access [4]byte, keyB [6]byte) [16]byte {
	var data [16]byte
	copy(data[0:6], keyA[:])
	copy(data[6:10], access[:])
	copy(data[10:16], keyB[:])
	return data
}

// trailerBlock returns the block number of a sector's trailer.
func trailerBlock(sector uint8) (uint8, error) {
	switch {
	case sector < 32:
		return sector*4 + 3, nil
	case sector < 40:
		return 128 + (sector-32)*16 + 15, nil
	}
	return 0, ErrInvalidArgument
}
