// Reads the UID of any ISO/IEC 14443-3 Type A card, and on a MIFARE Classic
// card also reads block 4 with the transport key.
//
// Wiring for an ESP32 with the reader on I2C0, SDA on GPIO21 and SCL on GPIO22.
package main

import (
	"machine"
	"time"

	"tinygo.org/x/drivers/pn512"
)

func main() {
	time.Sleep(2 * time.Second)

	err := machine.I2C0.Configure(machine.I2CConfig{
		Frequency: 100 * machine.KHz,
	})
	if err != nil {
		println("I2C0.Configure:", err.Error())
		return
	}

	reader := pn512.New(machine.I2C0)
	if err := reader.Configure(pn512.Config{}); err != nil {
		println("Configure:", err.Error())
		return
	}
	println("reader ready, hold a card against the antenna")

	for {
		card, err := reader.ReadCard()
		if err != nil {
			// An empty field gives ErrNoCard (idle state).
			if err != pn512.ErrNoCard {
				println("ReadCard:", err.Error())
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}

		println("UID", hex(card.Bytes()), "SAK", hex([]byte{card.SAK}), card.Type().String())

		readBlock(&reader, &card)

		// Release halts the card and clears the crypto unit. Without
		// this, the next poll would fail once before the card answers.
		reader.Release()
		time.Sleep(time.Second)
	}
}

func readBlock(reader *pn512.Device, card *pn512.Card) {
	if card.Type() != pn512.TypeClassic1K && card.Type() != pn512.TypeClassic4K {
		return
	}

	err := reader.Authenticate(pn512.KeyA, 4, pn512.DefaultKey, card.Bytes())
	if err != nil {
		println("Authenticate:", err.Error())
		return
	}

	block, err := reader.ReadBlock(4)
	if err != nil {
		println("ReadBlock:", err.Error())
		return
	}
	println("block 4:", hex(block[:]))
}

const digits = "0123456789ABCDEF"

func hex(b []byte) string {
	out := make([]byte, 0, len(b)*3)
	for i, v := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, digits[v>>4], digits[v&0x0F])
	}
	return string(out)
}
