package spartn

// TODO: Consider moving to separate package

import (
	"bufio"
	"errors"

	"github.com/snksoft/crc"
)

type MessageCRCType uint8

const (
	// TODD: Consider making these types so we only need one case statement (in Deserialization)
	CRC8CCITT    MessageCRCType = 0
	CRC16CCITT   MessageCRCType = 1
	CRC24Radix64 MessageCRCType = 2
	CRC32CCITT   MessageCRCType = 3
)

var (
	FrameHash *crc.Hash = crc.NewHash(&crc.Parameters{
		Width: 8,
		Polynomial: 0x09,
	})
)

func (t MessageCRCType) CalculateCRC(data []byte) (c uint32, err error) {
	switch t {
	case CRC8CCITT:
		hash := crc.NewHash(&crc.Parameters{
			Width:      8,
			Polynomial: 0x07,
		})
		return uint32(hash.CalculateCRC(data)), nil

	case CRC16CCITT:
		hash := crc.NewHash(&crc.Parameters{
			Width:      16,
			Polynomial: 0x1021,
		})
		return uint32(hash.CalculateCRC(data)), nil

	case CRC24Radix64:
		hash := crc.NewHash(&crc.Parameters{
			Width:      24,
			Polynomial: 0x864CFB,
		})
		return uint32(hash.CalculateCRC(data)), nil

	case CRC32CCITT:
		hash :=crc.NewHash(&crc.Parameters{
			Width:      32,
			Polynomial: 0x04C11DB7,
			Init:       0xFFFFFFFF,
			FinalXor:   0xFFFFFFFF,
		})
		return uint32(hash.CalculateCRC(data)), nil

	default:
		return c, errors.New("invalid CRC type")
	}
}

func DeserializeMessageCRC(t MessageCRCType, r *bufio.Reader) (c uint32, err error) {
	switch t {
	case CRC8CCITT:
		b, err := r.ReadByte()
		return uint32(b), err

	case CRC16CCITT:
		b := make([]byte, 2)
		_, err := r.Read(b)
		return uint32(b[0]) << 8 & uint32(b[1]), err

	case CRC24Radix64:
		b := make([]byte, 3)
		_, err := r.Read(b)
		return uint32(b[0]) << 16 & uint32(b[1]) << 8 & uint32(b[2]), err

	case CRC32CCITT:
		b := make([]byte, 4)
		_, err := r.Read(b)
		return uint32(b[0]) << 24 & uint32(b[1]) << 16 & uint32(b[2]) << 8 & uint32(b[3]), err

	default:
		return c, errors.New("invalid CRC Type")
	}
}

// FrameCRC
// Byte-by-byte 4-bit CRC calculated from TF002 through TF005.
// A4-bit 0x0 filler(4 bits) is added to the right of the rightmost bit of the TF002-TF005 bit sequence(20 bits).
// Therefore, a 24-bit sequence is used in the CRC computation.
// This is done in order to allow byte alignment of the buffer used for the CRC computation.
// The parameters of this CRC-4 are:
//   a. Polynomial = 0x09
//   b. Initialized at zero
//   c. Input is reflected.
//   d. Output is reflected.
//   e. Zero XOR on output.
