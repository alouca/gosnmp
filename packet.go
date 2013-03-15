package gosnmp

import (
	"bytes"
	"fmt"
	l "github.com/alouca/gologger"
	"strconv"
	"strings"
)

type SnmpVersion uint8

const (
	Version1  SnmpVersion = 0x0
	Version2c SnmpVersion = 0x1
)

func (s SnmpVersion) String() string {
	if s == Version1 {
		return "1"
	} else if s == Version2c {
		return "2c"
	}
	return "U"
}

type SnmpPacket struct {
	Version     SnmpVersion
	Community   string
	RequestType Asn1BER
	RequestID   uint8
	Error       uint8
	ErrorIndex  uint8
	Variables   []SnmpPDU
}

type SnmpPDU struct {
	Name  string
	Type  Asn1BER
	Value interface{}
}

func Unmarshal(packet []byte) (*SnmpPacket, error) {
	log := l.GetDefaultLogger()
	//var err error
	response := new(SnmpPacket)
	response.Variables = make([]SnmpPDU, 0, 5)

	// Start parsing the packet
	cursor := 0

	// First bytes should be 0x30
	if Asn1BER(packet[0]) == Sequence {
		// Parse packet length
		var length int
		// length of structure is spread over two bytes
		if packet[1] == 0x82 {
			length = int(packet[2])<<8 | int(packet[3])
			length += 4 // account for header + length
			cursor += 4

		} else {
			length = int(packet[1])
			length += 2 // account for header + length
			cursor += 2
		}

		if len(packet) == length {
			log.Debug("Packet sanity verified, we got all the bytes (%d)\n", length)
			// Parse SNMP Version
			rawVersion, count, err := parseRawField(packet[cursor:])

			if err != nil {
				return nil, fmt.Errorf("Error parsing SNMP packet version: %s", err.Error())
			}

			cursor += count
			if version, ok := rawVersion.(int); ok {
				response.Version = SnmpVersion(version)
			}

			// Parse community
			rawCommunity, count, err := parseRawField(packet[cursor:])
			cursor += count
			if community, ok := rawCommunity.(string); ok {
				response.Community = community
				log.Debug("Parsed community %s\n", community)
			}

			// Parse SNMP packet type
			switch Asn1BER(packet[cursor]) {
			case GetResponse:
				log.Debug("SNMP Packet is get response\n")
				response.RequestType = GetResponse

				// Response length (dont really care what the length is)
				if packet[cursor+1] == 0x82 {
					cursor += 4
				} else {
					cursor += 2
				}
				log.Debug("Response length: %d\n", length)

				// Parse Request ID
				rawRequestId, count, err := parseRawField(packet[cursor:])

				if err != nil {
					return nil, fmt.Errorf("Error parsing SNMP packet request ID: %s", err.Error())
				}

				cursor += count
				if requestid, ok := rawRequestId.(int); ok {
					response.RequestID = uint8(requestid)
				}

				// Parse Error
				rawError, count, err := parseRawField(packet[cursor:])

				if err != nil {
					return nil, fmt.Errorf("Error parsing SNMP packet error: %s", err.Error())
				}

				cursor += count
				if errorNo, ok := rawError.(int); ok {
					response.Error = uint8(errorNo)
				}

				// Parse Error Index
				rawErrorIndex, count, err := parseRawField(packet[cursor:])

				if err != nil {
					return nil, fmt.Errorf("Error parsing SNMP packet error index: %s", err.Error())
				}

				cursor += count
				if errorindex, ok := rawErrorIndex.(int); ok {
					response.ErrorIndex = uint8(errorindex)
				}

				log.Debug("Request ID: %d Error: %d Error Index: %d\n", response.RequestID, response.Error, response.ErrorIndex)

				// Varbind list
				if packet[cursor] == 0x30 && packet[cursor+1] == 0x82 {
					cursor += 4
				} else {
					cursor += 2
				}

				// Loop & parse Varbinds
				for cursor < length {
					log.Debug("Parsing var bind response (Cursor at %d/%d)", cursor, length)
					if packet[cursor] == 0x30 && packet[cursor+1] == 0x82 {
						cursor += 4
						log.Debug("Padded Varbind length\n")
					} else {
						cursor += 2
					}

					// Parse OID
					rawOid, count, err := parseRawField(packet[cursor:])
					cursor += count
					log.Debug("OID (%v) Field was %d bytes\n", rawOid, count)

					valueType, length, valueData := parseField(packet[cursor:])
					v, err := decodeValue(valueType, valueData)

					if err != nil {
						return nil, fmt.Errorf("Error parsing PDU Value: %s", err.Error())
					}

					if oid, ok := rawOid.([]int); ok {
						response.Variables = append(response.Variables, SnmpPDU{oidToString(oid), v.Type, v.Value})
					}
					cursor += int(length) + 1

				}

			}

		} else {
			return nil, fmt.Errorf("Error verifying packet sanity: Got %d Expected: %d\n", len(packet), length)
		}
	} else {
		return nil, fmt.Errorf("Invalid packet header\n")
	}

	return response, nil
}

// Parses a given field, return the ASN.1 BER Type, its lenght and the data
func parseField(data []byte) (Asn1BER, uint64, []byte) {
	log := l.GetDefaultLogger()

	var asn1type Asn1BER

	if len(data) == 0 {
		return 0, 0, nil
	}

	asn1type = Asn1BER(data[0])

	// Parse Length
	length := data[1]
	var finalLength uint64 = 2
	cursor := 0
	// Check if this is padded or not
	if length > 0x80 {
		length = length - 0x80
		log.Debug("Field length is padded to %d bytes\n", length)
		finalLength += Uvarint(data[2 : 2+length])
		log.Debug("Decoded final length: %d\n", finalLength)
		cursor = 2 + int(length)
	} else {
		finalLength += uint64(length)
		cursor = 2
	}

	return asn1type, finalLength, data[cursor:]
}

func parseRawField(data []byte) (interface{}, int, error) {
	switch Asn1BER(data[0]) {
	case Integer:
		length := int(data[1])
		if length == 1 {
			return int(data[2]), 3, nil
		} else {
			resp, err := parseInt(data[2:(1 + length)])
			return resp, 2 + length, err
		}
	case OctetString:
		length := int(data[1])
		return string(data[2 : 2+length]), length + 2, nil
	case ObjectIdentifier:
		length := int(data[1])
		oid, err := parseObjectIdentifier(data[2 : 2+length])
		return oid, length + 2, err
	default:
		return nil, 0, fmt.Errorf("Unknown field type: %x\n", data[0])
	}

	return nil, 0, nil
}

func (packet *SnmpPacket) marshal() ([]byte, error) {
	// Prepare the buffer to send
	buffer := make([]byte, 0, 1024)
	buf := bytes.NewBuffer(buffer)

	// Write the packet header (Message type 0x30) & Version = 2
	buf.Write([]byte{byte(Sequence), 0, 2, 1, byte(packet.Version)})

	// Write Community
	buf.Write([]byte{4, uint8(len(packet.Community))})
	buf.WriteString(packet.Community)

	// Marshal the SNMP PDU
	snmpPduBuffer := make([]byte, 0, 1024)
	snmpPduBuf := bytes.NewBuffer(snmpPduBuffer)

	snmpPduBuf.Write([]byte{byte(packet.RequestType), 0, 2, 1, packet.RequestID, 2, 1, packet.Error, 2, 1, packet.ErrorIndex, byte(Sequence), 0})

	pduLength := 0
	for _, varlist := range packet.Variables {
		pdu, err := marshalPDU(&varlist)

		if err != nil {
			return nil, err
		}
		pduLength += len(pdu)
		snmpPduBuf.Write(pdu)
	}

	pduBytes := snmpPduBuf.Bytes()
	// Varbind list length
	pduBytes[12] = byte(pduLength)
	// SNMP PDU length (PDU header + varbind list length)
	pduBytes[1] = byte(pduLength + 11)

	buf.Write(pduBytes)

	// Write the 
	//buf.Write([]byte{packet.RequestType, uint8(17 + len(mOid)), 2, 1, 1, 2, 1, 0, 2, 1, 0, 0x30, uint8(6 + len(mOid)), 0x30, uint8(4 + len(mOid)), 6, uint8(len(mOid))})
	//buf.Write(mOid)
	//buf.Write([]byte{5, 0})

	ret := buf.Bytes()

	// Set the packet size
	ret[1] = uint8(len(ret) - 2)

	return ret, nil
}

func marshalPDU(pdu *SnmpPDU) ([]byte, error) {
	oid, err := marshalOID(pdu.Name)
	if err != nil {
		return nil, err
	}

	pduBuffer := make([]byte, 0, 1024)
	pduBuf := bytes.NewBuffer(pduBuffer)

	// Mashal the PDU type into the appropriate BER
	switch pdu.Type {
	case Null:
		pduBuf.Write([]byte{byte(Sequence), byte(len(oid) + 4)})
		pduBuf.Write([]byte{byte(ObjectIdentifier), byte(len(oid))})
		pduBuf.Write(oid)
		pduBuf.Write([]byte{Null, 0x00})
	default:
		return nil, fmt.Errorf("Unable to marshal PDU: uknown BER type %d", pdu.Type)
	}

	return pduBuf.Bytes(), nil
}

func oidToString(oid []int) (ret string) {
	for _, i := range oid {
		ret = ret + fmt.Sprintf(".%d", i)
	}
	return
}

func marshalOID(oid string) ([]byte, error) {
	var err error

	// Encode the oid
	oid = strings.Trim(oid, ".")
	oidParts := strings.Split(oid, ".")
	oidBytes := make([]int, len(oidParts))

	// Convert the string OID to an array of integers
	for i := 0; i < len(oidParts); i++ {
		oidBytes[i], err = strconv.Atoi(oidParts[i])
		if err != nil {
			return nil, fmt.Errorf("Unable to parse OID: %s\n", err.Error())
		}
	}

	mOid, err := marshalObjectIdentifier(oidBytes)

	if err != nil {
		return nil, fmt.Errorf("Unable to marshal OID: %s\n", err.Error())
	}

	return mOid, err
}
