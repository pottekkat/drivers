// Package pn512 provides a driver for the NXP PN512 contactless reader. It
// supports reading ISO/IEC 14443-3 Type A cards and reading and writing MIFARE
// Classic memory. Only I2C is implemented.
package pn512

import (
	"errors"
	"runtime"
	"time"

	"tinygo.org/x/drivers"
)

// DefaultAddress is the address the PN512 answers at with its three address
// pins tied low. If any of these pins are tied high, it will answer elsewhere
// in 0x28 to 0x2F, which Configure can set (ref: 9.4.5).
const DefaultAddress uint16 = 0x28

var (
	// ErrNoCard is returned when nothing answered before the timer that
	// Config.Timeout sets expired. An empty field gives this, so it is a
	// normal result.
	ErrNoCard = errors.New("pn512: no card in field")

	// ErrNotDetected is returned by Configure when nothing on the bus
	// answers as a PN512.
	ErrNotDetected = errors.New("pn512: chip not detected")

	// ErrCollision is returned when more than one card answered. This
	// driver reads one card at a time.
	ErrCollision = errors.New("pn512: collision, more than one card")

	// ErrProtocol is returned when the chip reports a protocol error, or
	// an argument or reply is one this driver cannot handle.
	ErrProtocol = errors.New("pn512: protocol error")

	// ErrParity is returned when the chip reports a parity error on a reply.
	ErrParity = errors.New("pn512: parity error")

	// ErrCRC is returned when a reply's CRC_A does not match the one the
	// chip computes over the same bytes.
	ErrCRC = errors.New("pn512: CRC mismatch")

	// ErrBCC is returned when a UID and the check byte sent with it disagree.
	ErrBCC = errors.New("pn512: UID checksum mismatch")

	// ErrBufferOver is returned when a frame does not fit the chip's FIFO,
	// or a reply does not fit the buffer prepared for it.
	ErrBufferOver = errors.New("pn512: buffer overflow")

	// ErrShortFrame is returned when an exchange succeeded and the reply
	// was not the length the protocol requires.
	ErrShortFrame = errors.New("pn512: unexpected response length")

	// ErrTimeout is returned when the chip stopped responding.
	// Config.Timeout does not apply: that sets the chip's own card timer,
	// which gives ErrNoCard.
	ErrTimeout = errors.New("pn512: chip did not finish the command")

	// ErrBadGain is returned by Configure when Config.Gain has bits set
	// outside the receiver gain field.
	ErrBadGain = errors.New("pn512: receiver gain out of range")

	// ErrAuthFailed is returned by Authenticate when the card did not
	// accept the key. A wrong key, or the wrong key type for the sector,
	// is the usual cause.
	ErrAuthFailed = errors.New("pn512: MIFARE authentication failed")

	// ErrNACK is returned when a card refused a command with a code this
	// driver does not name.
	ErrNACK = errors.New("pn512: card refused the operation")

	// ErrNotPermitted is returned when the sector's access bits forbid the
	// operation with the key that opened the session.
	ErrNotPermitted = errors.New("pn512: access bits forbid the operation")

	// ErrTransmission is returned when a card reports that the frame
	// reached it corrupted.
	ErrTransmission = errors.New("pn512: card reported a transmission error")

	// ErrBlockProtected is returned by WriteBlock for block 0 and for
	// sector trailers. Use WriteTrailer for a trailer.
	ErrBlockProtected = errors.New("pn512: refusing to write a protected block")

	// ErrBadAccessBits is returned by ValidateAccess and WriteTrailer when
	// a trailer's access bytes are not self-consistent.
	ErrBadAccessBits = errors.New("pn512: access bits are not self-consistent")

	// ErrNotValueBlock is returned by DecodeValue when the 16 bytes are
	// not a value block.
	ErrNotValueBlock = errors.New("pn512: block is not a valid value block")

	// ErrChipReset is returned when the chip still answers the bus but has
	// lost the configuration Configure gave it.
	ErrChipReset = errors.New("pn512: chip lost its configuration, reset it")
)

// Gain sets the sensitivity of the receiver.
type Gain uint8

// Receiver gain settings (ref: 8.2.3.6).
const (
	Gain18dB Gain = 0x20
	Gain23dB Gain = 0x10
	Gain33dB Gain = 0x40
	Gain38dB Gain = 0x50
	Gain43dB Gain = 0x60
	Gain48dB Gain = 0x70
)

// Config holds the optional settings for Configure.
type Config struct {
	// Address is the chip's 7-bit I2C address. 0 means DefaultAddress.
	Address uint16

	// Gain is the receiver gain. 0 means Gain33dB.
	Gain Gain

	// Timeout is how long the chip waits for a card to answer before
	// giving up. 0 means 1ms.
	Timeout time.Duration
}

// Device is a PN512 on an I2C bus.
type Device struct {
	bus  drivers.I2C
	addr uint16

	wbuf [1 + 64]byte // 1 register address byte + 64 byte FIFO
	rbuf [1]byte
	fifo [64]byte // 64 byte FIFO maximum

	timeout time.Duration

	diag Diag
}

// Diag is the chip's view of the last exchange.
// Useful when the sentinel error is correct but not enough to debug with.
type Diag struct {
	// IRq is CommIRqReg as the poll loop last read it.
	IRq uint8

	// Error is ErrorReg, or 0 if the exchange never got that far.
	Error uint8

	// N is how many bytes received. Identifies the frame: ATQA is 2,
	// anticollision 5, and SAK 3.
	N int

	// Status2 is Status2Reg, read only after authentication. Bit 3 is MFCrypto1On.
	Status2 uint8

	// TxControl is TxControlReg, read only when the frame never went out.
	// 0x83 means the antenna drivers were on. 0x80 is the reset value.
	TxControl uint8

	// NAK is the card's raw four-bit refusal.
	NAK uint8
}

// BufferLost reports whether the card's last refusal also invalidated its
// transfer buffer. It is only meaningful after Increment, Decrement, Restore,
// or Transfer returned an error.
func (d Diag) BufferLost() bool { return bufferLost(d.NAK) }

// Diag returns the chip's view of the last exchange.
func (d *Device) Diag() Diag { return d.diag }

// New returns a Device for the given bus.
func New(bus drivers.I2C) Device {
	return Device{bus: bus, addr: DefaultAddress}
}

// Configure resets the chip and brings it up as an ISO/IEC 14443 Type A reader.
func (d *Device) Configure(cfg Config) error {
	if cfg.Address != 0 {
		d.addr = cfg.Address
	}

	gain := uint8(cfg.Gain)
	if gain == 0 {
		gain = uint8(Gain33dB)
	}
	if gain&^0x70 != 0 {
		return ErrBadGain
	}
	// Bit 3 is set in RFCfgReg's reset value. Preserving it.
	gain |= 0x08

	if err := d.reset(); err != nil {
		return err
	}

	if !d.Connected() {
		return ErrNotDetected
	}

	if err := d.setTimeout(cfg.Timeout); err != nil {
		return err
	}

	// Force100ASK (ref: 8.2.2.6).
	if err := d.writeReg(regTxAuto, 0x40); err != nil {
		return err
	}

	if err := d.writeReg(regMode, 0x3D); err != nil {
		return err
	}

	// 106 kbit/s, Type A framing, no automatic CRC (ref: 8.2.2.3).
	if err := d.writeReg(regTxMode, 0x00); err != nil {
		return err
	}

	// Same as the above for reception, and RxNoErr (ref 8.2.2.4).
	if err := d.writeReg(regRxMode, 0x08); err != nil {
		return err
	}

	if err := d.writeReg(regRFCfg, gain); err != nil {
		return err
	}

	// Act as initiator rather than target (ref: 8.2.1.13).
	if err := d.writeReg(regControl, ctrlInitiator); err != nil {
		return err
	}

	return d.SetAntenna(true)
}

// Connected reports whether a PN512 answers at the configured address.
func (d *Device) Connected() bool {
	d.wbuf[0] = regVersion
	if err := d.bus.Tx(d.addr, d.wbuf[:1], nil); err != nil {
		return false
	}
	v, err := d.Version()
	if err != nil {
		return false
	}
	return isKnownVersion(v)
}

// isKnownVersion reports whether v is a version this driver has been tested against.
// 0x80 indicates version 1.0 and 0x82 indicates version 2.0 (ref: 8.2.4.8).
func isKnownVersion(v uint8) bool {
	return v == 0x80 || v == 0x82
}

// Version returns the contents of VersionReg.
// 0x80 indicates version 1.0 and 0x82 indicates version 2.0 (ref: 8.2.4.8).
func (d *Device) Version() (uint8, error) {
	return d.readReg(regVersion)
}

// SetAntenna switches the two antenna drivers TX1 and TX2 (ref: 8.2.2.5).
func (d *Device) SetAntenna(on bool) error {
	v, err := d.readReg(regTxControl)
	if err != nil {
		return err
	}
	if on {
		v |= txRFEn
	} else {
		v &^= txRFEn
	}
	return d.writeReg(regTxControl, v)
}

// reset issues a soft reset and waits for the chip to come back.
func (d *Device) reset() error {
	if err := d.writeReg(regCommand, cmdSoftReset); err != nil {
		return err
	}

	for range 50 {
		time.Sleep(time.Millisecond)
		v, err := d.readReg(regCommand)
		if err != nil {
			continue
		}
		if v&0x10 == 0 {
			return nil
		}
	}
	return ErrTimeout
}

// setTimeout programs the chip's countdown timer (ref: 14).
func (d *Device) setTimeout(t time.Duration) error {
	if t <= 0 {
		t = time.Millisecond
	}
	d.timeout = t

	const prescaler = 0xD3E

	// At TPrescaler = 0xD3E, one tick is (2*3390 + 1) / 13.56MHz = 500.07us.
	// Dividing by 499us instead to always round up the result.
	ticks := min(max(t/(499*time.Microsecond), 1), 0xFFFF)

	if err := d.writeReg(regTMode, 0x80|uint8(prescaler>>8)); err != nil {
		return err
	}
	if err := d.writeReg(regTPrescaler, uint8(prescaler&0xFF)); err != nil {
		return err
	}
	if err := d.writeReg(regTReloadH, uint8(ticks>>8)); err != nil {
		return err
	}
	return d.writeReg(regTReloadL, uint8(ticks))
}

// readReg reads one register.
func (d *Device) readReg(reg uint8) (uint8, error) {
	d.wbuf[0] = reg
	if err := d.bus.Tx(d.addr, d.wbuf[:1], d.rbuf[:1]); err != nil {
		return 0, err
	}
	return d.rbuf[0], nil
}

func (d *Device) writeReg(reg, val uint8) error {
	d.wbuf[0] = reg
	d.wbuf[1] = val
	return d.bus.Tx(d.addr, d.wbuf[:2], nil)
}

func (d *Device) setBits(reg, mask uint8) error {
	v, err := d.readReg(reg)
	if err != nil {
		return err
	}
	return d.writeReg(reg, v|mask)
}

func (d *Device) clearBits(reg, mask uint8) error {
	v, err := d.readReg(reg)
	if err != nil {
		return err
	}
	return d.writeReg(reg, v&^mask)
}

// writeFIFO loads bytes into the 64-byte FIFO in a single transaction (ref: 9.4.6).
func (d *Device) writeFIFO(data []byte) error {
	if len(data) > len(d.wbuf)-1 {
		return ErrBufferOver
	}
	d.wbuf[0] = regFIFOData
	n := copy(d.wbuf[1:], data)
	return d.bus.Tx(d.addr, d.wbuf[:1+n], nil)
}

// crc runs the chip's CRC coprocessor over the data and returns the
// two result bytes in transmission order, low byte first (ref: 11.7.4).
func (d *Device) crc(data []byte) (lo, hi uint8, err error) {
	if err = d.writeReg(regCommand, cmdIdle); err != nil {
		return
	}
	if err = d.writeReg(regDivIRq, irqCRC); err != nil {
		return
	}
	if err = d.writeReg(regFIFOLevel, 0x80); err != nil {
		return
	}
	if err = d.writeFIFO(data); err != nil {
		return
	}
	if err = d.writeReg(regCommand, cmdCalcCRC); err != nil {
		return
	}

	for range 5000 {
		var v uint8
		if v, err = d.readReg(regDivIRq); err != nil {
			return
		}
		if v&irqCRC != 0 {
			if err = d.writeReg(regCommand, cmdIdle); err != nil {
				return
			}
			if lo, err = d.readReg(regCRCResultL); err != nil {
				return
			}
			hi, err = d.readReg(regCRCResultH)
			return
		}
	}
	err = ErrTimeout
	return
}

// transceive sends a frame and returns the reply.
func (d *Device) transceive(send []byte, sendLastBits uint8, recv []byte, rxAlign uint8) (n int, lastBits uint8, err error) {
	d.diag = Diag{}

	if err = d.writeReg(regCommand, cmdIdle); err != nil {
		return
	}
	// Clear every interrupt flag (ref: 8.2.1.5).
	if err = d.writeReg(regCommIRq, 0x7F); err != nil {
		return
	}
	if err = d.writeReg(regFIFOLevel, 0x80); err != nil {
		return
	}
	if err = d.writeFIFO(send); err != nil {
		return
	}
	framing := rxAlign<<4 | sendLastBits
	if err = d.writeReg(regBitFraming, framing); err != nil {
		return
	}
	if err = d.writeReg(regCommand, cmdTransceive); err != nil {
		return
	}

	// StartSend (ref: 8.2.1.14).
	if err = d.writeReg(regBitFraming, 0x80|framing); err != nil {
		return
	}

	deadline := time.Now().Add(100 * time.Millisecond)
	var irq uint8
	done := false
	for time.Now().Before(deadline) {
		if irq, err = d.readReg(regCommIRq); err != nil {
			return
		}
		if irq&(irqRx|irqIdle) != 0 {
			done = true
			break
		}
		if irq&irqTimer != 0 {
			done = true
			break
		}
		runtime.Gosched()
	}
	d.diag.IRq = irq

	if e := d.writeReg(regBitFraming, framing); e != nil {
		err = e
		return
	}
	if !done {
		if tx, e := d.readReg(regTxControl); e == nil {
			d.diag.TxControl = tx
			if tx&txRFEn == 0 {
				err = ErrChipReset
				return
			}
		}
		err = ErrTimeout
		return
	}
	if irq&(irqRx|irqIdle) == 0 {
		err = ErrNoCard
		return
	}

	var errReg uint8
	if errReg, err = d.readReg(regError); err != nil {
		return
	}
	d.diag.Error = errReg
	switch {
	case errReg&errBufferOv != 0:
		err = ErrBufferOver
		return
	case errReg&errParity != 0:
		err = ErrParity
		return
	case errReg&errProtocol != 0:
		err = ErrProtocol
		return
	case errReg&errColl != 0:
		err = ErrCollision
		return
	}

	var level uint8
	if level, err = d.readReg(regFIFOLevel); err != nil {
		return
	}
	d.diag.N = int(level)
	if int(level) > len(recv) {
		err = ErrBufferOver
		return
	}
	for i := 0; i < int(level); i++ {
		if recv[i], err = d.readReg(regFIFOData); err != nil {
			return
		}
	}
	n = int(level)

	// RxLastBits, ControlReg bits 2:0 (ref: 8.2.1.13).
	var ctrl uint8
	if ctrl, err = d.readReg(regControl); err != nil {
		return
	}
	lastBits = ctrl & 0x07
	return
}
