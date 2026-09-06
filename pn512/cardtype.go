package pn512

// ref: NXP AN10833 datasheet (Rev. 3.9 - 15 December 2025)
// https://www.nxp.com/docs/en/application-note/AN10833.pdf

// Type is a card family, obtained from ATQA and SAK.
type Type uint8

// Card families.
const (
	TypeUnknown Type = iota
	TypeClassic1K
	TypeClassic4K
	TypeClassicMini

	// TypeUltralight covers Ultralight, Ultralight EV1 and NTAG21x.
	TypeUltralight

	// TypeISO14443_4 cards speak the higher-layer transport.
	TypeISO14443_4
)

// String returns human-readable names.
func (t Type) String() string {
	switch t {
	case TypeClassic1K:
		return "MIFARE Classic 1K"
	case TypeClassic4K:
		return "MIFARE Classic 4K"
	case TypeClassicMini:
		return "MIFARE Mini"
	case TypeUltralight:
		return "MIFARE Ultralight or NTAG"
	case TypeISO14443_4:
		return "ISO 14443-4 card"
	}
	return "unknown"
}

// Type identifies the card family.
func (c *Card) Type() Type {
	if c.SAK&sakISO14443_4 != 0 {
		return TypeISO14443_4
	}
	// SAK is tested before ATQA.
	switch c.SAK {
	case sakClassic1K:
		return TypeClassic1K
	case sakClassic4K:
		return TypeClassic4K
	case sakClassicMini:
		return TypeClassicMini
	case sakUltralight:
		if c.ATQA[0] == atqaUltralight {
			return TypeUltralight
		}
	}
	return TypeUnknown
}
