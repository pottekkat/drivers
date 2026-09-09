# PN512 driver

Reads ISO/IEC 14443-3 Type A cards and reads and writes MIFARE Classic memory. I2C only.

## Usage

```go
machine.I2C0.Configure(machine.I2CConfig{Frequency: 100 * machine.KHz})

reader := pn512.New(machine.I2C0)
if err := reader.Configure(pn512.Config{}); err != nil {
	println(err.Error())
	return
}

card, err := reader.ReadCard()
if err == pn512.ErrNoCard {
	// Normal for an empty field.
}
```

An empty `Config` takes the defaults. See [examples/pn512](../examples/pn512/main.go) for a complete program.

Call `Halt` when you're done with a card, or `Release` if you authenticated one. Skip it and the next poll fails once before it succeeds.

`WriteBlock` refuses block 0 and the sector trailers. Use `WriteTrailer` for a trailer, because a wrong byte there locks the sector for good.

If the chip keeps answering the bus but stops behaving, call `Configure` again. The supply dipping under the antenna drive can reset the module while the host keeps running.

## Limitations

- Reader only. The chip can also act as a card or an NFCIP-1 peer.
- Type A at 106 kbit/s. No Type B, no FeliCa, no higher bit rates.
- No ISO/IEC 14443-4 transport. `Card.Type` reports such a card, but nothing more.
- MIFARE Classic only for memory. Ultralight and NTAG are named but can't be read or written.
- One card at a time.
- No 10-byte UIDs.
- Polling only. The IRQ pin is unused.

## Hardware

Developed against an SI512, a PN512 clone by Nanjing CSM that answers at 0x28. Tested on an ESP32 with the `esp32-mini32` target, I2C0 at 100 kHz, SDA on GPIO21 and SCL on GPIO22, against MIFARE Classic 1K cards.

Cards with 7-byte UIDs and the 4K block layout are implemented but untested.
