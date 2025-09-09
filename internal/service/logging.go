package service

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
	"github.com/slavasuhoveev/shelf-auth/internal/security"
	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

type AuthService struct {
	users    UsersReader
	sessions SessionsWriter
	signer   tokens.Signer

	accessTTL  time.Duration
	refreshTTL time.Duration

	pwOptions security.Options // bcrypt options (cost, pepper)
}

func NewAuthService(users UsersReader, sessions SessionsWriter, signer tokens.Signer, accessTTL, refreshTTL time.Duration, pwOptions security.Options) *AuthService {
	return &AuthService{
		users:     users,
		sessions:  sessions,
		signer:    signer,
		accessTTL: accessTTL, refreshTTL: refreshTTL,
		pwOptions: pwOptions,
	}
}

type LoginResult struct {
	AccessToken string    `json:"access_token"`
	AccessExp   time.Time `json:"access_expires_at"`
	// Raw refresh token is not serialized in JSON — it goes to HttpOnly cookie in handler.
	RefreshToken string    `json:"-"`
	RefreshExp   time.Time `json:"-"`
}

// Login authenticates the user, creates a refresh session and returns tokens.
// DeviceID is provided by the client (e.g., random UUID per browser profile).
func (s *AuthService) Login(ctx context.Context, emailRaw, password, deviceID, ip, ua string) (*LoginResult, error) {
	email, err := domain.ParseEmail(emailRaw)
	if err != nil {
		return nil, domain.ErrInvalidCredentials // don't leak validation details on login
	}

	u, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	if err := security.CheckPassword(u.PasswordHash, password, s.pwOptions); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if !u.EmailVerified {
		return nil, domain.ErrEmailNotVerified
	}

	// Issue access token
	access, accessExp, err := s.signer.SignAccess(tokens.AccessClaims{
		UserID: u.ID,
		Email:  u.Email.String(),
	}, s.accessTTL)
	if err != nil {
		return nil, err
	}

	// Create refresh token (opaque) and session
	rawRefresh, err := security.GenerateOpaqueToken(32) // 256-bit
	if err != nil {
		return nil, err
	}
	refreshHash := security.HashSHA256Hex(rawRefresh)

	// A unique JTI for the refresh instance; reuse the raw refresh as JTI seed is OK or generate separate.
	jti, err := security.GenerateOpaqueToken(16) // 128-bit ID
	if err != nil {
		return nil, err
	}

	sess, err := domain.NewSession(u.ID, deviceID, jti, refreshHash, ip, ua, s.refreshTTL)
	if err != nil {
		return nil, err
	}

	if err := s.sessions.Create(ctx, sess); err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  access,
		AccessExp:    accessExp,
		RefreshToken: rawRefresh,
		RefreshExp:   sess.ExpiresAt,
	}, nil
}
