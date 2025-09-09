package service

import "github.com/slavasuhoveev/shelf-auth/internal/auth/signer"

// Service is the application business logic layer.
// For now it only holds dependencies and exposes no methods.
type Service struct {
	signer *signer.Signer
}

// New creates a new Service instance.
func New(db interface{}, s *signer.Signer) *Service {
	return &Service{signer: s}
}
