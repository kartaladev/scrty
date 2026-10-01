package gorm

import (
	"time"

	"github.com/kartaladev/scrty/pkg/id"
)

// The models map the tables the migrate package creates, one struct per table.
// Nothing here creates or alters a table: no store calls AutoMigrate, and the
// schema is the migration's alone.
//
// Every column is named with an explicit column tag and every table with a
// TableName method, so a consumer's naming strategy never renames them. Every
// column carries its type, and none a default or an automatic time: gorm
// leaves a zero value out of an insert for a column with a default, and fills
// an automatic time itself, and either would store something other than the
// record the store was given. TestModels pins all of this against the
// migration file.
//
// An integer is an int64 whatever its column's width, so a value the column
// cannot hold is an error from PostgreSQL, never truncated in Go.
//
// Times are stored UTC, truncated to the microsecond (see storekit.Time), and
// a nullable time is a *time.Time, NULL for nil. A nullable identifier is an
// *id.ID, NULL for nil: id.ID itself writes the nil identifier as the all-zero
// UUID, not NULL, and cannot scan NULL.

// sessionRow is a row of the sessions table. The session identifier is never
// stored: IDDigest is its SHA-256, and ID a primary key the store mints.
type sessionRow struct {
	ID                    id.ID      `gorm:"column:id;type:uuid;primaryKey"`
	IDDigest              []byte     `gorm:"column:id_digest;type:bytea"`
	UserID                string     `gorm:"column:user_id;type:text"`
	CreatedAt             time.Time  `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
	LastAccessedAt        time.Time  `gorm:"column:last_accessed_at;type:timestamptz"`
	IdleExpiresAt         time.Time  `gorm:"column:idle_expires_at;type:timestamptz"`
	AbsoluteExpiresAt     time.Time  `gorm:"column:absolute_expires_at;type:timestamptz"`
	FirstFactor           string     `gorm:"column:first_factor;type:text"`
	MFAState              int64      `gorm:"column:mfa_state;type:smallint"`
	MFASatisfiedAt        *time.Time `gorm:"column:mfa_satisfied_at;type:timestamptz"`
	PasswordChangePending bool       `gorm:"column:password_change_pending;type:boolean"`
	ExternalProvider      string     `gorm:"column:external_provider;type:text"`
	ExternalIssuer        string     `gorm:"column:external_issuer;type:text"`
	ExternalSessionID     string     `gorm:"column:external_session_id;type:text"`
	ExternalIDToken       string     `gorm:"column:external_id_token;type:text"`
	Data                  string     `gorm:"column:data;type:jsonb"`
	// EnrolmentOriginDeadline is NULL for a session not marked
	// enrolment-only, and EnrolmentGeneration NULL for one that has begun
	// no enrolment.
	EnrolmentOriginDeadline *time.Time `gorm:"column:enrolment_origin_deadline;type:timestamptz"`
	EnrolmentGeneration     *id.ID     `gorm:"column:enrolment_generation;type:uuid"`
	// RecoveredAt is NULL for a session no account recovery ever produced.
	RecoveredAt *time.Time `gorm:"column:recovered_at;type:timestamptz"`
	// MFAAtFirstFactor is written by the insert only; the update omits it.
	MFAAtFirstFactor bool `gorm:"column:mfa_at_first_factor;type:boolean"`
}

// TableName is the table the migration creates for sessions.
func (sessionRow) TableName() string { return "sessions" }

// oneTimeTokenRow is a row of the one_time_tokens table, keyed by the token's
// own identifier. A nil BindingHash is NULL, an unbound token; a nil
// ConsumedAt is an unspent one.
type oneTimeTokenRow struct {
	ID          id.ID      `gorm:"column:id;type:uuid;primaryKey"`
	Purpose     string     `gorm:"column:purpose;type:text"`
	Subject     string     `gorm:"column:subject;type:text"`
	SecretHash  []byte     `gorm:"column:secret_hash;type:bytea"`
	BindingHash []byte     `gorm:"column:binding_hash;type:bytea"`
	IssuedAt    time.Time  `gorm:"column:issued_at;type:timestamptz"`
	ExpiresAt   time.Time  `gorm:"column:expires_at;type:timestamptz"`
	ConsumedAt  *time.Time `gorm:"column:consumed_at;type:timestamptz"`
}

// TableName is the table the migration creates for one-time tokens.
func (oneTimeTokenRow) TableName() string { return "one_time_tokens" }

// loginAttemptRow is a row of the login_attempts table: one failure, keyed by
// an identifier the store mints.
type loginAttemptRow struct {
	ID          id.ID     `gorm:"column:id;type:uuid;primaryKey"`
	Username    string    `gorm:"column:username;type:text"`
	AttemptedAt time.Time `gorm:"column:attempted_at;type:timestamptz"`
}

// TableName is the table the migration creates for login attempts.
func (loginAttemptRow) TableName() string { return "login_attempts" }

// signingKeyRow is a row of the signing_keys table, keyed by a primary key the
// store mints and found by its kid. PrivateKey holds the sealed private
// material; PublicJWK is published and stored as given.
type signingKeyRow struct {
	ID         id.ID     `gorm:"column:id;type:uuid;primaryKey"`
	Kid        string    `gorm:"column:kid;type:text"`
	Alg        string    `gorm:"column:alg;type:text"`
	PrivateKey []byte    `gorm:"column:private_key;type:bytea"`
	PublicJWK  []byte    `gorm:"column:public_jwk;type:bytea"`
	CreatedAt  time.Time `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
}

// TableName is the table the migration creates for signing keys.
func (signingKeyRow) TableName() string { return "signing_keys" }

// enrolmentRow is a row of the mfa_enrolments table, one per user, keyed by a
// primary key the store mints. Secret is the sealed secret, base64url-encoded;
// a nil ConfirmedAt is a pending enrolment. The enrolment path's fields are
// nullable: a nil Generation is an enrolment with no generation, which no
// conditional write matches; a nil DeviceProvenAt an unproven device; a nil
// EmailCode, the sealed code base64url-encoded, no outstanding code.
type enrolmentRow struct {
	ID                id.ID      `gorm:"column:id;type:uuid;primaryKey"`
	UserID            string     `gorm:"column:user_id;type:text"`
	Secret            string     `gorm:"column:secret;type:text"`
	ConfirmedAt       *time.Time `gorm:"column:confirmed_at;type:timestamptz"`
	LastStep          int64      `gorm:"column:last_step;type:bigint"`
	CreatedAt         time.Time  `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
	Generation        *id.ID     `gorm:"column:generation;type:uuid"`
	DeviceProvenAt    *time.Time `gorm:"column:device_proven_at;type:timestamptz"`
	EmailCode         *string    `gorm:"column:email_code;type:text"`
	EmailCodeUntil    *time.Time `gorm:"column:email_code_until;type:timestamptz"`
	EmailCodeAttempts int64      `gorm:"column:email_code_attempts;type:integer"`
}

// TableName is the table the migration creates for MFA enrolments.
func (enrolmentRow) TableName() string { return "mfa_enrolments" }

// apiKeyRow is a row of the api_keys table, keyed by the key's own
// identifier. Scopes is a JSON array of strings; a nil time is NULL, absent.
type apiKeyRow struct {
	ID           id.ID      `gorm:"column:id;type:uuid;primaryKey"`
	UserID       string     `gorm:"column:user_id;type:text"`
	Name         string     `gorm:"column:name;type:text"`
	Scopes       string     `gorm:"column:scopes;type:jsonb"`
	SecretDigest []byte     `gorm:"column:secret_digest;type:bytea"`
	ExpiresAt    *time.Time `gorm:"column:expires_at;type:timestamptz"`
	RevokedAt    *time.Time `gorm:"column:revoked_at;type:timestamptz"`
	LastUsedAt   *time.Time `gorm:"column:last_used_at;type:timestamptz"`
	CreatedAt    time.Time  `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
}

// TableName is the table the migration creates for API keys.
func (apiKeyRow) TableName() string { return "api_keys" }

// linkRow is a row of the oidc_links table, keyed by the link's own
// identifier and unique by provider, issuer and subject.
type linkRow struct {
	ID        id.ID     `gorm:"column:id;type:uuid;primaryKey"`
	Provider  string    `gorm:"column:provider;type:text"`
	Issuer    string    `gorm:"column:issuer;type:text"`
	Subject   string    `gorm:"column:subject;type:text"`
	UserID    string    `gorm:"column:user_id;type:text"`
	Username  string    `gorm:"column:username;type:text"`
	Email     string    `gorm:"column:email;type:text"`
	CreatedAt time.Time `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
}

// TableName is the table the migration creates for OIDC links.
func (linkRow) TableName() string { return "oidc_links" }

// flowRow is a row of the oidc_flows table, keyed by a primary key the store
// mints and found by its handle. A nil CompletedAt is an uncompleted flow.
type flowRow struct {
	ID          id.ID      `gorm:"column:id;type:uuid;primaryKey"`
	Handle      string     `gorm:"column:handle;type:text"`
	Provider    string     `gorm:"column:provider;type:text"`
	State       string     `gorm:"column:state;type:text"`
	Nonce       string     `gorm:"column:nonce;type:text"`
	Verifier    string     `gorm:"column:verifier;type:text"`
	Next        string     `gorm:"column:next;type:text"`
	ExpiresAt   time.Time  `gorm:"column:expires_at;type:timestamptz"`
	CompletedAt *time.Time `gorm:"column:completed_at;type:timestamptz"`
}

// TableName is the table the migration creates for OIDC flows.
func (flowRow) TableName() string { return "oidc_flows" }

// handoffRow is a row of the oidc_handoffs table, keyed by the record's own
// identifier and found by its token id. A nil ConsumedAt is an unconsumed
// record.
type handoffRow struct {
	ID         id.ID      `gorm:"column:id;type:uuid;primaryKey"`
	TokenID    string     `gorm:"column:token_id;type:text"`
	SecretHash []byte     `gorm:"column:secret_hash;type:bytea"`
	UserID     string     `gorm:"column:user_id;type:text"`
	Provider   string     `gorm:"column:provider;type:text"`
	Issuer     string     `gorm:"column:issuer;type:text"`
	SessionID  string     `gorm:"column:session_id;type:text"`
	IDToken    string     `gorm:"column:id_token;type:text"`
	Next       string     `gorm:"column:next;type:text"`
	ExpiresAt  time.Time  `gorm:"column:expires_at;type:timestamptz"`
	CreatedAt  time.Time  `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
	ConsumedAt *time.Time `gorm:"column:consumed_at;type:timestamptz"`
}

// TableName is the table the migration creates for OIDC handoffs.
func (handoffRow) TableName() string { return "oidc_handoffs" }

// userRow is a row of the users table of the identity migration set, keyed by
// an identifier the identity store mints. Password is never NULL: a user with
// no credential stores an empty hash. A nil OrganizationID is no organization,
// and a nil PasswordChangedAt no recorded change. CreatedAt and UpdatedAt are
// the store clock's, never gorm's.
type userRow struct {
	ID                id.ID      `gorm:"column:id;type:uuid;primaryKey"`
	Name              string     `gorm:"column:name;type:text"`
	Username          string     `gorm:"column:username;type:text"`
	Password          []byte     `gorm:"column:password;type:bytea"`
	Active            bool       `gorm:"column:active;type:boolean"`
	Role              string     `gorm:"column:role;type:text"`
	OrganizationID    *id.ID     `gorm:"column:organization_id;type:uuid"`
	PasswordChangedAt *time.Time `gorm:"column:password_changed_at;type:timestamptz"`
	MFARequired       bool       `gorm:"column:mfa_required;type:boolean"`
	CreatedAt         time.Time  `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
	UpdatedAt         time.Time  `gorm:"column:updated_at;type:timestamptz;autoUpdateTime:false"`
}

// TableName is the table the identity migration creates for users.
func (userRow) TableName() string { return "users" }

// assignedRoleRow is a row of the assigned_roles table of the identity
// migration set: one role grant, keyed by its own identifier and ordered by
// Position, never by that identifier. A nil StartDate or ValidUntil is an
// open end of the grant's validity window.
type assignedRoleRow struct {
	ID         id.ID      `gorm:"column:id;type:uuid;primaryKey"`
	UserID     id.ID      `gorm:"column:user_id;type:uuid"`
	RoleName   string     `gorm:"column:role_name;type:text"`
	Position   int64      `gorm:"column:position;type:integer"`
	IsPrimary  bool       `gorm:"column:is_primary;type:boolean"`
	SuperRole  bool       `gorm:"column:super_role;type:boolean"`
	StartDate  *time.Time `gorm:"column:start_date;type:timestamptz"`
	ValidUntil *time.Time `gorm:"column:valid_until;type:timestamptz"`
	CreatedAt  time.Time  `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;type:timestamptz;autoUpdateTime:false"`
}

// TableName is the table the identity migration creates for role grants.
func (assignedRoleRow) TableName() string { return "assigned_roles" }

// recoveryCodeRow is a row of the recovery_codes table: one saved recovery
// code's hash, keyed by an identifier the store mints and found by its user
// and hash. A nil SpentAt is an unspent code. CreatedAt is the caller's,
// never gorm's.
type recoveryCodeRow struct {
	ID        id.ID      `gorm:"column:id;type:uuid;primaryKey"`
	UserID    string     `gorm:"column:user_id;type:text"`
	CodeHash  []byte     `gorm:"column:code_hash;type:bytea"`
	CreatedAt time.Time  `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
	SpentAt   *time.Time `gorm:"column:spent_at;type:timestamptz"`
}

// TableName is the table the migration creates for saved recovery codes.
func (recoveryCodeRow) TableName() string { return "recovery_codes" }

// accountRecoveryRow is a row of the account_recoveries table, keyed by the
// record's own identifier. A nil CompletedAt or CancelledAt is a record not
// yet completed or cancelled. Proven and Reported hold the authenticator
// references as internal/pgschema writes them. SavedSpent carries no gorm
// default, so a false value is written, never left to the column's.
type accountRecoveryRow struct {
	ID          id.ID      `gorm:"column:id;type:uuid;primaryKey"`
	UserID      string     `gorm:"column:user_id;type:text"`
	StartedAt   time.Time  `gorm:"column:started_at;type:timestamptz"`
	NotBefore   time.Time  `gorm:"column:not_before;type:timestamptz"`
	CompletedAt *time.Time `gorm:"column:completed_at;type:timestamptz"`
	CancelledAt *time.Time `gorm:"column:cancelled_at;type:timestamptz"`
	Proven      string     `gorm:"column:proven;type:text"`
	Reported    string     `gorm:"column:reported;type:text"`
	SavedSpent  bool       `gorm:"column:saved_spent;type:boolean"`
}

// TableName is the table the migration creates for account recoveries.
func (accountRecoveryRow) TableName() string { return "account_recoveries" }
