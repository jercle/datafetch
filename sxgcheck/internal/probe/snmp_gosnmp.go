package probe

import (
	"context"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/jercle/datafetch/sxgcheck/internal/config"
)

// This file is the only one that imports gosnmp.

type goSNMP struct{ g *gosnmp.GoSNMP }

// NewGoSNMP opens an SNMP v2c or v3 session over UDP.
func NewGoSNMP(ctx context.Context, host string, s *config.SNMP, timeout time.Duration) (SNMPClient, error) {
	g := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(s.Port),
		Transport: "udp",
		Context:   ctx,
		Timeout:   timeout,
		Retries:   1,
		MaxOids:   gosnmp.MaxOids,
	}
	if s.Version == "3" {
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		usm := &gosnmp.UsmSecurityParameters{UserName: s.Username}
		g.MsgFlags = gosnmp.NoAuthNoPriv
		if s.AuthPassword != "" {
			g.MsgFlags = gosnmp.AuthNoPriv
			usm.AuthenticationPassphrase = s.AuthPassword
			usm.AuthenticationProtocol = map[string]gosnmp.SnmpV3AuthProtocol{
				"MD5": gosnmp.MD5, "SHA": gosnmp.SHA, "SHA224": gosnmp.SHA224,
				"SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512,
			}[s.AuthProtocol]
		}
		if s.PrivPassword != "" {
			g.MsgFlags = gosnmp.AuthPriv
			usm.PrivacyPassphrase = s.PrivPassword
			usm.PrivacyProtocol = map[string]gosnmp.SnmpV3PrivProtocol{
				"DES": gosnmp.DES, "AES": gosnmp.AES, "AES192": gosnmp.AES192, "AES256": gosnmp.AES256,
			}[s.PrivProtocol]
		}
		g.SecurityParameters = usm
	} else {
		g.Version = gosnmp.Version2c
		g.Community = s.Community
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	return &goSNMP{g}, nil
}

func collect(out map[string]any, pdus []gosnmp.SnmpPDU) {
	for _, pdu := range pdus {
		name := strings.TrimPrefix(pdu.Name, ".")
		switch pdu.Type {
		case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		case gosnmp.OctetString:
			if b, ok := pdu.Value.([]byte); ok {
				out[name] = string(b)
			}
		case gosnmp.IPAddress, gosnmp.ObjectIdentifier:
			if s, ok := pdu.Value.(string); ok {
				out[name] = s
			}
		default:
			out[name] = gosnmp.ToBigInt(pdu.Value).Int64()
		}
	}
}

func (c *goSNMP) Get(oids []string) (map[string]any, error) {
	dotted := make([]string, len(oids))
	for i, o := range oids {
		dotted[i] = "." + o
	}
	pkt, err := c.g.Get(dotted)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	collect(out, pkt.Variables)
	return out, nil
}

func (c *goSNMP) Walk(root string) (map[string]any, error) {
	pdus, err := c.g.BulkWalkAll("." + root)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	collect(out, pdus)
	return out, nil
}

func (c *goSNMP) Close() error {
	if c.g.Conn == nil {
		return nil
	}
	return c.g.Conn.Close()
}
