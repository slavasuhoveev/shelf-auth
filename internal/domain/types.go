package domain

import (
	"net"

	"github.com/google/uuid"
)

// ID is a generic numeric identifier used by entities persisted in the DB.
type ID struct {
	uuid.UUID
}

func NewID() ID {
	return ID{UUID: uuid.New()}
}

func ParseID(s string) (ID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return ID{}, err
	}
	return ID{UUID: u}, nil
}

func (id ID) String() string {
	return id.UUID.String()
}

func (id ID) IsZero() bool {
	return id.UUID == uuid.Nil
}

func NewIPFromNet(ip net.IP) *IP {
	if ip == nil {
		return nil
	}
	return &IP{IP: ip}
}
