package spartn

import (
	"bufio"
	"errors"
)

const (
	FramePreamble uint8 = 0x73
)

// Frame is used to encapsulate encoded SPARTN Messages, supplying
// encryption and authentication information.
type Frame struct {
	Preamble                     uint8          // 8
	MessageType                  uint8          // 7
	PayloadLength                uint16         // 10
	EAF                          bool           // 1
	MessageCRCType               MessageCRCType // 2
	CRC                          uint8          // 4
	MessageSubtype               uint8          // 4
	TimeTagType                  bool           // 1
	TimeTag                      uint32         // TimeTagType ? 16bits : 32bits
	SolutionID                   uint8          // 7
	SolutionProcessorID          uint8          // 4
	EncryptionID                 uint8          // 4
	EncryptionSequenceNumber     uint8          // 6
	AuthenticationIndicator      uint8          // 3
	EmbeddedAuthenticationLength uint8          // 3
	MessagePayload               []byte         // SizeOf MessageLength - padded
	EmbeddedAuthenticationData   []byte         // SizeOf EmbeddedAuthenticationLength
	MessageCRC                   uint32         // 8 - 32
}

// DeserializeFrame only discards a single byte from the given Reader
// if no valid preamble is found, or if the Frame CRC is invalid.
//
// Discards bytes from Reader whether or not the MessageCRC is valid.
func DeserializeFrame(r *bufio.Reader) (frame Frame, err error) {
	frame.Preamble, err = r.ReadByte()
	if err != nil {
		return frame, err
	}
	if frame.Preamble != FramePreamble {
		return frame, errors.New("invalid preamble")
	}

	frameHeader, err := DeserializeFrameStart(r, &frame)
	if ; err != nil {
		return frame, err
	}

	payloadDescription, err := DeserializePayloadDescriptionBlock(r, &frame)
	if ; err != nil {
		return frame, err
	}

	frame.MessagePayload = make([]byte, frame.PayloadLength)
	_, err = r.Read(frame.MessagePayload)
	if err != nil {
		return frame, err
	}

	frame.EmbeddedAuthenticationData = make([]byte, frame.EmbeddedAuthenticationLength)
	_, err = r.Read(frame.EmbeddedAuthenticationData)
	if err != nil {
		return frame, err
	}

	frame.MessageCRC, err = DeserializeMessageCRC(frame.MessageCRCType, r)
	if err != nil {
		return frame, err
	}

	// TODO: Implement Serialize method for Frame, instead of collecting and joining parsed []byte
	crc, _ := frame.MessageCRCType.CalculateCRC(append(frameHeader, append(
		payloadDescription, append(
			frame.MessagePayload, frame.EmbeddedAuthenticationData...)...)...))

	if crc != frame.MessageCRC {
		return frame, errors.New("message CRC does not match computed value")
	}

	return frame, err
}

// DeserializeFrameStart discards bytes from Reader only if CRC is valid.
func DeserializeFrameStart(r *bufio.Reader, frame *Frame) (frameHeader []byte, err error) {
	frameHeader, err = r.Peek(3)
	if err != nil {
		return frameHeader, err
	}

	frame.MessageType = frameHeader[0] >> 1

	frame.PayloadLength = (uint16(frameHeader[0]&0x01) << 9 &
		uint16(frameHeader[1]) << 1 &
		uint16(frameHeader[2]) >> 7)

	frame.EAF = (frameHeader[2] & 0x40) >> 6 == 0x01

	frame.MessageCRCType = MessageCRCType((frameHeader[2] & 0x30) >> 4)
	frame.CRC = frameHeader[2] & 0x0F

	if uint8(FrameHash.CalculateCRC(frameHeader[:2])) != frame.CRC {
		return frameHeader, errors.New("frame CRC did not match calculated value")
	}

	_, err = r.Discard(3)

	return frameHeader, err
}

func DeserializePayloadDescriptionBlock(r *bufio.Reader, frame *Frame) (parsedBytes []byte, err error) {
	// Consider only peeking 6 bytes ahead until TimeTagType is checked
	payloadDescription, err := r.Peek(8)
	if err != nil {
		return parsedBytes, err
	}
	parsedBytes = payloadDescription

	frame.MessageSubtype = payloadDescription[0] >> 4

	frame.TimeTagType = (payloadDescription[0] & 0x04) >> 3 == 0x01
	frame.TimeTag = (
		uint32(payloadDescription[0] & 0x07) << 13 &
		uint32(payloadDescription[1]) << 5 &
		uint32(payloadDescription[2] & 0xF8) >> 3)

	if frame.TimeTagType { // parse 16 more bits into TimeTag
		frame.TimeTag = (
			frame.TimeTag << 16 &
			uint32(payloadDescription[2] & 0x07) << 13 &
			uint32(payloadDescription[3]) << 5 &
			uint32(payloadDescription[4] & 0xF8) >> 3)

		_, err = r.Discard(8)
		payloadDescription = payloadDescription[4:]
	} else {
		_, err = r.Discard(6)
		parsedBytes = payloadDescription[:6]
		payloadDescription = payloadDescription[2:]
	}

	if err != nil {
		return parsedBytes, err
	}

	frame.SolutionID = (
		(payloadDescription[0] & 0x07) << 4 &
		(payloadDescription[1] & 0xF0) >> 4)
	frame.SolutionProcessorID = payloadDescription[1] & 0x0F

	frame.EncryptionID = (payloadDescription[2] & 0xF0) >> 4
	frame.EncryptionSequenceNumber = (
		(payloadDescription[2] & 0x0F) << 4 &
		(payloadDescription[3] & 0xC0) >> 6)

	frame.AuthenticationIndicator = (payloadDescription[3] & 0x38) >> 3
	frame.EmbeddedAuthenticationLength = payloadDescription[3] & 0x7

	return parsedBytes, nil
}
