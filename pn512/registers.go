package pn512

// ref: NXP PN512 datasheet (Rev. 5.3 - 17 March 2020, 111353)
// https://www.nxp.com/docs/en/data-sheet/PN512.pdf

// Register addresses (ref: 8.2).
const (
	// Page 0: Command and status (ref: 8.2.1).
	regCommand    = 0x01
	regCommIEn    = 0x02
	regDivIEn     = 0x03
	regCommIRq    = 0x04
	regDivIRq     = 0x05 // where CRCIRq lands, not CommIRqReg. See irqCRC below.
	regError      = 0x06
	regStatus1    = 0x07
	regStatus2    = 0x08 // holds MFCrypto1On. See status2Crypto1On below.
	regFIFOData   = 0x09
	regFIFOLevel  = 0x0A
	regWaterLevel = 0x0B
	regControl    = 0x0C // holds Initiator. See ctrlInitiator below.
	regBitFraming = 0x0D
	regColl       = 0x0E

	// Page 1: Communication (ref: 8.2.2).
	regMode        = 0x11
	regTxMode      = 0x12
	regRxMode      = 0x13
	regTxControl   = 0x14
	regTxAuto      = 0x15
	regTxSel       = 0x16
	regRxSel       = 0x17
	regRxThreshold = 0x18
	regDemod       = 0x19
	regTypeB       = 0x1E

	// Page 2: Configuration (ref: 8.2.3).
	regCRCResultH = 0x21
	regCRCResultL = 0x22
	regModWidth   = 0x24
	regRFCfg      = 0x26
	regGsNOn      = 0x27
	regCWGsP      = 0x28
	regModGsP     = 0x29
	regTMode      = 0x2A // top four bits of the timer prescaler live here, not in TPrescalerReg
	regTPrescaler = 0x2B
	regTReloadH   = 0x2C
	regTReloadL   = 0x2D

	// Page 3: Test (ref: 8.2.4).
	regVersion = 0x37
)

// Commands (ref: 18.3, table 158).
const (
	cmdIdle        = 0x00
	cmdCalcCRC     = 0x03
	cmdTransmit    = 0x04
	cmdNoCmdChange = 0x07
	cmdReceive     = 0x08
	cmdTransceive  = 0x0C
	cmdMFAuthent   = 0x0E
	cmdSoftReset   = 0x0F
)

// CommIRqReg bits (ref: 8.2.1.5, tables 25, 26).
//
// transceive polls for these flags. The reset value is 0x14, IdleIRq and
// LoAlertIRq both set. A loop that waits on IdleIRq without first clearing the
// register would return on its first read, before the frame has gone out, and
// then read a FIFO that never received anything. The 0x7F write at the top of
// transceive is for this.
const (
	irqTimer   = 1 << 0
	irqErr     = 1 << 1
	irqLoAlert = 1 << 2
	irqHiAlert = 1 << 3
	irqIdle    = 1 << 4
	irqRx      = 1 << 5
	irqTx      = 1 << 6
	irqSet1    = 1 << 7
)

// DivIRqReg bits (ref: 8.2.1.6, tables 27, 28).
const (
	irqCRC = 1 << 2
)

// ErrorReg bits (ref: 8.2.1.7, table 30).
const (
	errProtocol = 1 << 0
	errParity   = 1 << 1
	errCRC      = 1 << 2
	errColl     = 1 << 3
	errBufferOv = 1 << 4
	errTemp     = 1 << 6
	errWrErr    = 1 << 7
)

// TxControlReg bits (ref: 8.2.2.5, table 56).
const (
	txRFEn = 1<<1 | 1<<0 // Tx2RFEn (bit 1) and Tx1RFEn (bit 0)
)

// ControlReg bits (ref: 8.2.1.13, table 42).
const (
	ctrlInitiator = 1 << 4
)

// Status2Reg bits (ref: 8.2.1.9, table 34).
const (
	status2Crypto1On = 1 << 3
)

// Commands sent to the card and not to the chip.
// ref: NXP MF1S50YYX_V1 9.1 (Rev. 3.2 — 23 May 2018, 279232)
// https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf
const (
	piccREQA = 0x26
	piccWUPA = 0x52
	piccHLTA = 0x50
	piccCT   = 0x88 // ref: table 33

	// These are only half-commands:
	// 93h 20h and 95h 20h for anticollision
	// 93h 70h and 95h 70h for select
	piccSelCL1 = 0x93
	piccSelCL2 = 0x95

	piccRead      = 0x30
	piccWrite     = 0xA0
	piccDecrement = 0xC0
	piccIncrement = 0xC1
	piccRestore   = 0xC2
	piccTransfer  = 0xB0
)

// MIFARE Classic ACK/NAK.
// ref: NXP MF1S50YYX_V1 9.3, table 10
const (
	mifareACK = 0x0A

	mifareNAKInvalidOp    = 0x00
	mifareNAKTransmission = 0x01
	mifareNAKBufferLost   = 0x04
)

// Card identification bytes.
// ref: NXP application note AN10833 (Rev. 3.9 - 15 December 2025)
// https://www.nxp.com/docs/en/application-note/AN10833.pdf
const (
	sakClassic1K   = 0x08
	sakClassic4K   = 0x18
	sakClassicMini = 0x09 // ref: figure 1
	sakUltralight  = 0x00
	sakISO14443_4  = 0x20 // mask, not a value
	atqaUltralight = 0x44
)
