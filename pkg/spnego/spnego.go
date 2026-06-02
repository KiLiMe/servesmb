package spnego

import (
	"encoding/asn1"

	"github.com/geoffgarside/ber"
)

var (
	SpnegoOid     = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 2})
	MsKerberosOid = asn1.ObjectIdentifier([]int{1, 2, 840, 48018, 1, 2, 2})
	KerberosOid   = asn1.ObjectIdentifier([]int{1, 2, 840, 113554, 1, 2, 2})
	NlmpOid       = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 2, 2, 10})
)

type initialContextToken struct {
	ThisMech asn1.ObjectIdentifier `asn1:"optional"`
	Init     []NegTokenInit        `asn1:"optional,explict,tag:0"`
	Resp     []NegTokenResp        `asn1:"optional,explict,tag:1"`
}

type initialContextToken2 struct {
	ThisMech asn1.ObjectIdentifier `asn1:"optional"`
	Init2    []NegTokenInit2       `asn1:"optional,explict,tag:0"`
	Resp     []NegTokenResp        `asn1:"optional,explict,tag:1"`
}

type initialContextToken3 struct {
	ThisMech asn1.ObjectIdentifier  `asn1:"optional"`
	Init     []NegTokenInit         `asn1:"optional,explict,tag:0"`
	Resp     []NegTokenRespAccepted `asn1:"optional,explict,tag:1"`
}

type NegTokenInit struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,optional,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken   []byte                  `asn1:"explicit,optional,tag:2"`
	MechListMIC []byte                  `asn1:"explicit,optional,tag:3"`
}

var negHints = asn1.RawValue{ // not_defined_in_RFC4178@please_ignore
	FullBytes: []byte{
		0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f,
		0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73,
		0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65,
	},
}

type NegTokenInit2 struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,optional,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken   []byte                  `asn1:"explicit,optional,tag:2"`
	NegHints    asn1.RawValue           `asn1:"explicit,optional,tag:3"`
	MechListMIC []byte                  `asn1:"explicit,optional,tag:4"`
}

type NegTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"optional,explicit,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"optional,explicit,tag:1"`
	ResponseToken []byte                `asn1:"optional,explicit,tag:2"`
	MechListMIC   []byte                `asn1:"optional,explicit,tag:3"`
}

type NegTokenRespAccepted struct {
	NegState asn1.Enumerated `asn1:"explicit,tag:0"`
}

func DecodeNegTokenInit2(bs []byte) (*NegTokenInit2, error) {
	var init initialContextToken2
	_, err := ber.UnmarshalWithParams(bs, &init, "application,tag:0")
	if err != nil {
		return nil, err
	}
	return &init.Init2[0], nil
}

func EncodeNegTokenInit2(types []asn1.ObjectIdentifier) ([]byte, error) {
	bs, err := asn1.Marshal(initialContextToken2{ThisMech: SpnegoOid, Init2: []NegTokenInit2{{MechTypes: types, NegHints: negHints}}})
	if err != nil {
		return nil, err
	}
	bs[0] = 0x60
	return bs, nil
}

func EncodeNegTokenInit(types []asn1.ObjectIdentifier, token []byte) ([]byte, error) {
	bs, err := asn1.Marshal(initialContextToken{ThisMech: SpnegoOid, Init: []NegTokenInit{{MechTypes: types, MechToken: token}}})
	if err != nil {
		return nil, err
	}
	bs[0] = 0x60
	return bs, nil
}

func DecodeNegTokenInit(bs []byte) (*NegTokenInit, error) {
	var init initialContextToken
	_, err := ber.UnmarshalWithParams(bs, &init, "application,tag:0")
	if err != nil {
		return nil, err
	}
	return &init.Init[0], nil
}

func EncodeNegTokenResp(state asn1.Enumerated, typ asn1.ObjectIdentifier, token, mechListMIC []byte) ([]byte, error) {
    bs, err := asn1.Marshal(initialContextToken{Resp: []NegTokenResp{{NegState: state, SupportedMech: typ, ResponseToken: token, MechListMIC: mechListMIC}}})
    if err != nil {
        return nil, err
    }
    skip := 1
    if bs[skip] < 128 {
        skip += 1
    } else {
        skip += int(bs[skip]) - 128 + 1
    }
    return bs[skip:], nil
}

// EncodeNegTokenRespFull encodes a SPNEGO NegTokenResp and returns the full
// GSS-API InitialContextToken (starting with 0x60 ...), which some clients
// expect inside SMB2 SESSION_SETUP security buffers.
func EncodeNegTokenRespFull(state asn1.Enumerated, typ asn1.ObjectIdentifier, token, mechListMIC []byte) ([]byte, error) {
    bs, err := asn1.Marshal(initialContextToken{ThisMech: SpnegoOid, Resp: []NegTokenResp{{NegState: state, SupportedMech: typ, ResponseToken: token, MechListMIC: mechListMIC}}})
    if err != nil {
        return nil, err
    }
    // Ensure application tag 0x60
    bs[0] = 0x60
    return bs, nil
}

func EncodeNegTokenAccepted() ([]byte, error) {
    bs, err := asn1.Marshal(initialContextToken3{Resp: []NegTokenRespAccepted{{NegState: 0}}})
    if err != nil {
        return nil, err
    }
    skip := 1
    if bs[skip] < 128 {
        skip += 1
    } else {
        skip += int(bs[skip]) - 128 + 1
    }
    return bs[skip:], nil
}

// EncodeNegTokenAcceptedFull returns a full InitialContextToken-wrapped
// NegTokenRespAccepted for clients that expect the 0x60 wrapper.
func EncodeNegTokenAcceptedFull() ([]byte, error) {
    bs, err := asn1.Marshal(initialContextToken3{ThisMech: SpnegoOid, Resp: []NegTokenRespAccepted{{NegState: 0}}})
    if err != nil {
        return nil, err
    }
    bs[0] = 0x60
    return bs, nil
}

// EncodeNegTokenRespAcceptCompletedMIC returns a bare SPNEGO NegTokenResp
// (context [1]) carrying negState=accept-completed and a mechListMIC. Windows,
// Samba and macOS require this token when integrity (NTLMSSP SIGN/SEAL) was
// negotiated; without the server's mechListMIC they treat the handshake as
// tampered (SEC_E_MESSAGE_ALTERED / "failed to verify mechListMIC").
//
// The structure is fixed and small, so it is built directly to guarantee the
// exact DER the peers expect:
//
//	A1 LL                              -- [1] NegTokenResp
//	  30 LL                            --   SEQUENCE
//	    A0 03 0A 01 00                 --     negState [0] ENUMERATED accept-completed(0)
//	    A3 LL 04 LL <mic>              --     mechListMIC [3] OCTET STRING
func EncodeNegTokenRespAcceptCompletedMIC(mic []byte) []byte {
	negState := []byte{0xA0, 0x03, 0x0A, 0x01, 0x00}
	micField := append([]byte{0xA3, byte(2 + len(mic)), 0x04, byte(len(mic))}, mic...)
	inner := append(negState, micField...)
	seq := append([]byte{0x30, byte(len(inner))}, inner...)
	return append([]byte{0xA1, byte(len(seq))}, seq...)
}

// MechListDER extracts the raw DER bytes of the MechTypeList (the SEQUENCE OF
// MechType) from a SPNEGO NegTokenInit GSS token. These exact bytes are what
// both peers run the mechListMIC over, so the raw encoding is preserved rather
// than re-marshaled.
func MechListDER(token []byte) ([]byte, error) {
	var t struct {
		ThisMech asn1.ObjectIdentifier `asn1:"optional"`
		Init     []struct {
			MechTypes asn1.RawValue `asn1:"explicit,optional,tag:0"`
		} `asn1:"optional,explicit,tag:0"`
	}
	if _, err := ber.UnmarshalWithParams(token, &t, "application,tag:0"); err != nil {
		return nil, err
	}
	if len(t.Init) == 0 || len(t.Init[0].MechTypes.FullBytes) == 0 {
		return nil, asn1.SyntaxError{Msg: "spnego: missing MechTypeList"}
	}
	return t.Init[0].MechTypes.FullBytes, nil
}

func EncodeNegTokenRejected() ([]byte, error) {
	bs, err := asn1.Marshal(initialContextToken3{Resp: []NegTokenRespAccepted{{NegState: 2}}})
	if err != nil {
		return nil, err
	}
	skip := 1
	if bs[skip] < 128 {
		skip += 1
	} else {
		skip += int(bs[skip]) - 128 + 1
	}
	return bs[skip:], nil
}

func DecodeNegTokenResp(bs []byte) (*NegTokenResp, error) {
	var resp NegTokenResp
	_, err := ber.UnmarshalWithParams(bs, &resp, "explicit,tag:1")
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
