package pn512

import "time"

// ref: ISO/IEC 14443-3

// Anticollision constants.
const (
	nvbNoUID   = 0x20
	nvbFullUID = 0x70
	sakCascade = 0x04
)

// Card is an ISO 14443-3 Type A card.
type Card struct {
	UID    [7]byte
	UIDLen int
	ATQA   [2]byte
	SAK    uint8
}

// Bytes returns the UID.
func (c *Card) Bytes() []byte { return c.UID[:c.UIDLen] }

// Request sends REQA and returns the ATQA. Only a card in IDLE answers REQA.
func (d *Device) Request() ([2]byte, error) { return d.requestOrWake(piccREQA) }

// Wakeup sends WUPA and returns ATQA. Also wakes a halted card.
func (d *Device) Wakeup() ([2]byte, error) { return d.requestOrWake(piccWUPA) }

// requestOrWake sends a 7-bit short frame and expects a 2-byte ATQA.
func (d *Device) requestOrWake(cmd uint8) ([2]byte, error) {
	var atqa [2]byte

	// ValuesAfterColl must be 0 for the bitwise anticollision
	// that follows (ref: PN512 rev 5.3, 8.2.1.15).
	if err := d.writeReg(regColl, 0x00); err != nil {
		return atqa, err
	}

	buf := d.fifo[:2]
	n, _, err := d.transceive([]byte{cmd}, 7, buf, 0)
	if err != nil {
		return atqa, err
	}

	if n != 2 {
		return atqa, ErrShortFrame
	}
	atqa[0], atqa[1] = buf[0], buf[1]
	return atqa, nil
}

// ReadCard wakes a card, resolves its UID, and selects it.
// It returns ErrNoCard for an empty field while polling.
func (d *Device) ReadCard() (Card, error) {
	var c Card

	atqa, err := d.Wakeup()
	if err != nil {
		return c, err
	}
	c.ATQA = atqa

	levels := [2]uint8{piccSelCL1, piccSelCL2}
	for _, sel := range levels {
		uid, sak, err := d.cascadeLevel(sel)
		if err != nil {
			return c, err
		}
		c.SAK = sak

		if sak&sakCascade != 0 {
			if uid[0] != piccCT {
				return c, ErrProtocol
			}
			copy(c.UID[c.UIDLen:], uid[1:4])
			c.UIDLen += 3
			continue
		}

		if c.UIDLen == 0 && uid[0] == piccCT {
			return c, ErrProtocol
		}
		copy(c.UID[c.UIDLen:], uid[0:4])
		c.UIDLen += 4
		return c, nil
	}
	return c, ErrProtocol
}

// cascadeLevel runs ANTICOLLISION and SELECT for one level.
// It returns the four UID bytes of that level and the SAK.
func (d *Device) cascadeLevel(sel uint8) (uid [4]byte, sak uint8, err error) {
	buf := d.fifo[:16]

	n, _, err := d.transceive([]byte{sel, nvbNoUID}, 0, buf, 0)
	if err != nil {
		return
	}
	if n != 5 {
		err = ErrShortFrame
		return
	}
	if buf[0]^buf[1]^buf[2]^buf[3] != buf[4] {
		err = ErrBCC
		return
	}
	copy(uid[:], buf[0:4])

	var frame [9]byte
	frame[0] = sel
	frame[1] = nvbFullUID
	copy(frame[2:6], uid[:])
	frame[6] = buf[4]
	if frame[7], frame[8], err = d.crc(frame[:7]); err != nil {
		return
	}

	n, _, err = d.transceive(frame[:], 0, buf, 0)
	if err != nil {
		return
	}
	if n != 3 {
		err = ErrShortFrame
		return
	}
	var lo, hi uint8
	if lo, hi, err = d.crc(buf[0:1]); err != nil {
		return
	}
	if lo != buf[1] || hi != buf[2] {
		err = ErrCRC
		return
	}
	sak = buf[0]
	return
}

// Halt puts the selected card into HALT. Call it when done with a card, or the
// next poll will fail once before the card answers again.
// Send HLTA encrypted after successful authentication, or the card will refuse.
func (d *Device) Halt() error {
	var frame [4]byte
	frame[0] = piccHLTA
	frame[1] = 0x00
	lo, hi, err := d.crc(frame[:2])
	if err != nil {
		return err
	}
	frame[2], frame[3] = lo, hi

	// Any answer within 1 ms of the frame means the card refused.
	if saved := d.timeout; saved < time.Millisecond {
		if err = d.setTimeout(time.Millisecond); err != nil {
			return err
		}
		defer d.setTimeout(saved)
	}

	_, _, err = d.transceive(frame[:], 0, d.fifo[:4], 0)
	if err == ErrNoCard || err == ErrTimeout {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrProtocol
}
