// Package mobile is a gomobile-friendly wrapper around securetcp.
//
// Build example:
//
//	gomobile bind -target=android -o securetcp.aar ./mobile
package mobile

import (
	"context"
	"encoding/json"
	"time"

	"securetcp"
)

type Client struct{ inner *securetcp.Client }

func GenerateKeyPairJSON() (string, error) {
	kp, err := securetcp.GenerateKeyPair()
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(kp)
	return string(b), err
}

func NewClient(address, clientPrivateKeyB64, serverPublicKeyB64 string) (*Client, error) {
	c, err := securetcp.NewClient(securetcp.ClientConfig{
		Address:             address,
		ClientPrivateKeyB64: clientPrivateKeyB64,
		ServerPublicKeyB64:  serverPublicKeyB64,
		AutoReconnect:       true,
		CommonConfig: securetcp.CommonConfig{
			ReadTimeout:     60 * time.Second,
			WriteTimeout:    15 * time.Second,
			HeartbeatBase:   20 * time.Second,
			HeartbeatJitter: 8 * time.Second,
			RekeyInterval:   10 * time.Minute,
			OldKeyGrace:     30 * time.Second,
		},
	})
	if err != nil {
		return nil, err
	}
	return &Client{inner: c}, nil
}

func (c *Client) Connect() error         { return c.inner.Connect(context.Background()) }
func (c *Client) Send(data []byte) error { return c.inner.Write(context.Background(), data) }
func (c *Client) Recv() ([]byte, error)  { return c.inner.Read(context.Background()) }
func (c *Client) Close() error           { return c.inner.Close() }
