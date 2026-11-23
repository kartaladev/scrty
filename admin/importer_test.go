package admin_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
)

const importID = identity.UserID("0192f1e2-3c4d-7e5f-8a9b-0c1d2e3f4a5b")

var importHash = []byte("$2a$10$knownbcrypthashknownbcrypthashknownbcrypthashknownb")

func importedAda() admin.ImportedUser {
	return admin.ImportedUser{
		ID: importID, Username: "ada", Name: "Ada", Email: "ada@example.com",
		EmailVerifiedAt: time.Date(2021, 3, 4, 0, 0, 0, 0, time.UTC),
		PasswordHash:    append([]byte(nil), importHash...), Active: true,
		CreatedAt: time.Date(2021, 3, 4, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2022, 3, 4, 0, 0, 0, 0, time.UTC),
		Roles:     []string{"sales"}, Attributes: map[string]string{"job_title": "Manager"},
	}
}

func TestNewImporter(t *testing.T) {
	t.Parallel()

	var nilStore *MockImportStore

	type testCase struct {
		name   string
		build  func(t *testing.T) (*admin.Importer, error)
		assert func(t *testing.T, im *admin.Importer, err error)
	}

	refused := func(t *testing.T, im *admin.Importer, err error) {
		assert.ErrorIs(t, err, admin.ErrConfig)
		assert.Nil(t, im)
	}
	store := func(t *testing.T) admin.ImportStore { return NewMockImportStore(gomock.NewController(t)) }
	rec := func(t *testing.T) *MockRecognizer { return NewMockRecognizer(gomock.NewController(t)) }

	cases := []testCase{
		{name: "store and recogniser", build: func(t *testing.T) (*admin.Importer, error) {
			return admin.NewImporter(store(t), rec(t))
		}, assert: func(t *testing.T, im *admin.Importer, err error) {
			require.NoError(t, err)
			assert.NotNil(t, im)
		}},
		{name: "nil store", build: func(t *testing.T) (*admin.Importer, error) {
			return admin.NewImporter(nil, rec(t))
		}, assert: refused},
		{name: "typed nil store", build: func(t *testing.T) (*admin.Importer, error) {
			return admin.NewImporter(nilStore, rec(t))
		}, assert: refused},
		{name: "nil recogniser", build: func(t *testing.T) (*admin.Importer, error) {
			return admin.NewImporter(store(t), nil)
		}, assert: refused},
		{name: "attribute limits zero", build: func(t *testing.T) (*admin.Importer, error) {
			return admin.NewImporter(store(t), rec(t), admin.WithAttributeLimits(0, 1, 1))
		}, assert: refused},
		{name: "nil event sink", build: func(t *testing.T) (*admin.Importer, error) {
			return admin.NewImporter(store(t), rec(t), admin.WithEventSink(nil))
		}, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			im, err := tc.build(t)
			tc.assert(t, im, err)
		})
	}
}

func TestImporter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		input  func() admin.ImportedUser
		ctx    func(t *testing.T) context.Context
		setup  func(store *MockImportStore, rec *MockRecognizer)
		assert func(t *testing.T, out admin.ImportOutcome, err error, events []event.Event)
	}

	recognised := func(rec *MockRecognizer) { rec.EXPECT().Recognizes(importHash).Return(true).AnyTimes() }
	returns := func(out admin.ImportOutcome, err error) func(*MockImportStore, *MockRecognizer) {
		return func(store *MockImportStore, rec *MockRecognizer) {
			recognised(rec)
			store.EXPECT().ImportUser(gomock.Any(), gomock.Any()).Return(out, err)
		}
	}
	refusedNoCall := func(t *testing.T, out admin.ImportOutcome, err error, events []event.Event) {
		require.ErrorIs(t, err, admin.ErrInvalidInput)
		assert.Zero(t, out)
		assert.Empty(t, events)
	}
	with := func(change func(u *admin.ImportedUser)) func() admin.ImportedUser {
		return func() admin.ImportedUser {
			u := importedAda()
			change(&u)

			return u
		}
	}

	cases := []testCase{
		{
			name:  "empty identifier",
			input: with(func(u *admin.ImportedUser) { u.ID = "" }),
			setup: func(*MockImportStore, *MockRecognizer) {}, assert: refusedNoCall,
		},
		{
			name:  "blank identifier",
			input: with(func(u *admin.ImportedUser) { u.ID = "  " }),
			setup: func(*MockImportStore, *MockRecognizer) {}, assert: refusedNoCall,
		},
		{
			name:  "non-canonical identifier is the store's to judge",
			input: with(func(u *admin.ImportedUser) { u.ID = "0192F1E2-3C4D-7E5F-8A9B-0C1D2E3F4A5B" }),
			setup: returns(0, admin.ErrInvalidInput),
			assert: func(t *testing.T, out admin.ImportOutcome, err error, events []event.Event) {
				require.ErrorIs(t, err, admin.ErrInvalidInput)
				assert.Zero(t, out)
				assert.Empty(t, events)
			},
		},
		{
			name:  "identifier not a UUID reaches the store",
			input: with(func(u *admin.ImportedUser) { u.ID = "ada" }),
			setup: returns(admin.ImportCreated, nil),
			assert: func(t *testing.T, out admin.ImportOutcome, err error, _ []event.Event) {
				require.NoError(t, err)
				assert.Equal(t, admin.ImportCreated, out)
			},
		},
		{
			name:  "unrecognised hash",
			input: importedAda,
			setup: func(_ *MockImportStore, rec *MockRecognizer) {
				rec.EXPECT().Recognizes(importHash).Return(false)
			},
			assert: refusedNoCall,
		},
		{
			name:  "blank username",
			input: with(func(u *admin.ImportedUser) { u.Username = " " }),
			setup: func(_ *MockImportStore, rec *MockRecognizer) { recognised(rec) }, assert: refusedNoCall,
		},
		{
			name:  "username with surrounding space",
			input: with(func(u *admin.ImportedUser) { u.Username = "ada " }),
			setup: func(_ *MockImportStore, rec *MockRecognizer) { recognised(rec) }, assert: refusedNoCall,
		},
		{
			name:  "role with surrounding space",
			input: with(func(u *admin.ImportedUser) { u.Roles = []string{" sales"} }),
			setup: func(_ *MockImportStore, rec *MockRecognizer) { recognised(rec) }, assert: refusedNoCall,
		},
		{
			name:  "username beyond the bound",
			input: with(func(u *admin.ImportedUser) { u.Username = strings.Repeat("a", admin.MaxTextBytes+1) }),
			setup: func(_ *MockImportStore, rec *MockRecognizer) { recognised(rec) }, assert: refusedNoCall,
		},
		{
			name:  "blank email",
			input: with(func(u *admin.ImportedUser) { u.Email = "  " }),
			setup: func(_ *MockImportStore, rec *MockRecognizer) { recognised(rec) }, assert: refusedNoCall,
		},
		{
			name:  "verified time without an email",
			input: with(func(u *admin.ImportedUser) { u.Email = "" }),
			setup: func(_ *MockImportStore, rec *MockRecognizer) { recognised(rec) }, assert: refusedNoCall,
		},
		{
			name: "too many attributes",
			input: with(func(u *admin.ImportedUser) {
				u.Attributes = map[string]string{}
				for i := range admin.DefaultAttributeCount + 1 {
					u.Attributes[strings.Repeat("a", i+1)] = "v"
				}
			}),
			setup: func(_ *MockImportStore, rec *MockRecognizer) { recognised(rec) }, assert: refusedNoCall,
		},
		{
			name:  "blank role",
			input: with(func(u *admin.ImportedUser) { u.Roles = []string{""} }),
			setup: func(_ *MockImportStore, rec *MockRecognizer) { recognised(rec) }, assert: refusedNoCall,
		},
		{
			name:  "no actor",
			input: importedAda,
			ctx:   func(t *testing.T) context.Context { return t.Context() },
			setup: func(*MockImportStore, *MockRecognizer) {},
			assert: func(t *testing.T, _ admin.ImportOutcome, err error, events []event.Event) {
				require.ErrorIs(t, err, admin.ErrNoActor)
				assert.Empty(t, events)
			},
		},
		{
			name:  "created reports the import",
			input: importedAda,
			ctx: func(t *testing.T) context.Context {
				return admin.WithSystemActor(t.Context(), "sync")
			},
			setup: returns(admin.ImportCreated, nil),
			assert: func(t *testing.T, out admin.ImportOutcome, err error, events []event.Event) {
				require.NoError(t, err)
				assert.Equal(t, admin.ImportCreated, out)
				require.Len(t, events, 1)
				assert.Equal(t, event.UserImported, events[0].Name)
				assert.Equal(t, event.OutcomeSuccess, events[0].Outcome)
				assert.Equal(t, "system:sync", events[0].Actor)
				assert.Equal(t, string(importID), events[0].Target)
				assert.Equal(t, importID, events[0].User)
				assert.Equal(t, testNow, events[0].At)
			},
		},
		{
			name: "updated reports the import", input: importedAda, setup: returns(admin.ImportUpdated, nil),
			assert: func(t *testing.T, out admin.ImportOutcome, err error, events []event.Event) {
				require.NoError(t, err)
				assert.Equal(t, admin.ImportUpdated, out)
				require.Len(t, events, 1)
				assert.Equal(t, event.UserImported, events[0].Name)
			},
		},
		{
			name: "unchanged reports nothing", input: importedAda, setup: returns(admin.ImportUnchanged, nil),
			assert: func(t *testing.T, out admin.ImportOutcome, err error, events []event.Event) {
				require.NoError(t, err)
				assert.Equal(t, admin.ImportUnchanged, out)
				assert.Empty(t, events)
			},
		},
		{
			name:  "the store's already-exists error passes through",
			input: importedAda,
			setup: returns(0, admin.AlreadyExistsError{Field: admin.FieldUsername}),
			assert: func(t *testing.T, _ admin.ImportOutcome, err error, events []event.Event) {
				require.ErrorIs(t, err, admin.ErrAlreadyExists)
				var ae admin.AlreadyExistsError
				require.ErrorAs(t, err, &ae)
				assert.Equal(t, admin.FieldUsername, ae.Field)
				assert.NotContains(t, err.Error(), "ada")
				assert.Empty(t, events)
			},
		},
		{
			name: "storage failure matches no reason", input: importedAda, setup: returns(0, errStorage),
			assert: func(t *testing.T, _ admin.ImportOutcome, err error, events []event.Event) {
				require.ErrorIs(t, err, errStorage)
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
				assert.Empty(t, events)
			},
		},
		{
			name: "an outcome the store does not define is an error", input: importedAda, setup: returns(0, nil),
			assert: func(t *testing.T, out admin.ImportOutcome, err error, events []event.Event) {
				require.Error(t, err)
				assert.Zero(t, out)
				assert.Empty(t, events)
			},
		},
		{
			name:  "an empty hash is a user with no password",
			input: with(func(u *admin.ImportedUser) { u.PasswordHash = nil }),
			setup: func(store *MockImportStore, _ *MockRecognizer) {
				store.EXPECT().ImportUser(gomock.Any(), gomock.Any()).Return(admin.ImportCreated, nil)
			},
			assert: func(t *testing.T, out admin.ImportOutcome, err error, _ []event.Event) {
				require.NoError(t, err)
				assert.Equal(t, admin.ImportCreated, out)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			store, rec := NewMockImportStore(ctrl), NewMockRecognizer(ctrl)
			tc.setup(store, rec)

			events := &eventRecorder{}
			im, err := admin.NewImporter(store, rec, admin.WithEventSink(events.sink), admin.WithClock(fixedClock()))
			require.NoError(t, err)

			ctx := actorCtx(t)
			if tc.ctx != nil {
				ctx = tc.ctx(t)
			}

			out, err := im.Import(ctx, tc.input())
			tc.assert(t, out, err, events.all())
		})
	}
}

// TestImporter_WritesGivenValues pins that the store receives the hash and
// times exactly as given, the password policy unapplied, and a copy the
// caller cannot change afterwards.
func TestImporter_WritesGivenValues(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	store, rec := NewMockImportStore(ctrl), NewMockRecognizer(ctrl)
	rec.EXPECT().Recognizes(importHash).Return(true)

	in := importedAda()

	var got admin.ImportedUser
	store.EXPECT().ImportUser(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, u admin.ImportedUser) (admin.ImportOutcome, error) {
			got = u
			in.Attributes["job_title"] = "changed"
			in.PasswordHash[0] = 'X'
			in.Roles[0] = "changed"

			return admin.ImportCreated, nil
		})

	im, err := admin.NewImporter(store, rec)
	require.NoError(t, err)

	_, err = im.Import(actorCtx(t), in)
	require.NoError(t, err)

	want := importedAda()
	assert.Equal(t, want, got)
}

var _ = errors.New

// TestImporter_Times pins that the service passes the times as given: a zero
// time means "not given", for the store to fill on creation only, so two
// imports of one payload reach the store alike. An update before the creation
// is refused when both are given.
func TestImporter_Times(t *testing.T) {
	t.Parallel()

	created := time.Date(2021, 3, 4, 0, 0, 0, 0, time.UTC)

	type testCase struct {
		name             string
		created, updated time.Time
		assert           func(t *testing.T, got []admin.ImportedUser, err error)
	}

	cases := []testCase{
		{
			name: "update before creation", created: created, updated: created.Add(-time.Second),
			assert: func(t *testing.T, got []admin.ImportedUser, err error) {
				require.ErrorIs(t, err, admin.ErrInvalidInput)
				assert.Empty(t, got, "the store is not called")
			},
		},
		{
			name: "zero times reach the store as zero on every run",
			assert: func(t *testing.T, got []admin.ImportedUser, err error) {
				require.NoError(t, err)
				require.Len(t, got, 2)
				for _, u := range got {
					assert.True(t, u.CreatedAt.IsZero())
					assert.True(t, u.UpdatedAt.IsZero())
				}
			},
		},
		{
			name: "a zero update time is not checked against the creation", created: created,
			assert: func(t *testing.T, got []admin.ImportedUser, err error) {
				require.NoError(t, err)
				require.Len(t, got, 2)
				assert.Equal(t, created, got[1].CreatedAt)
				assert.True(t, got[1].UpdatedAt.IsZero())
			},
		},
		{
			name: "given times are kept", created: created, updated: created.Add(time.Hour),
			assert: func(t *testing.T, got []admin.ImportedUser, err error) {
				require.NoError(t, err)
				require.Len(t, got, 2)
				assert.Equal(t, got[0], got[1])
				assert.Equal(t, created.Add(time.Hour), got[1].UpdatedAt)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			store, rec := NewMockImportStore(ctrl), NewMockRecognizer(ctrl)
			rec.EXPECT().Recognizes(gomock.Any()).Return(true).AnyTimes()

			var got []admin.ImportedUser
			store.EXPECT().ImportUser(gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, u admin.ImportedUser) (admin.ImportOutcome, error) {
					got = append(got, u)

					return admin.ImportUnchanged, nil
				}).AnyTimes()

			// The clock moves between the runs, so a service-side default
			// would differ between them.
			clk := fixedClock()
			im, err := admin.NewImporter(store, rec, admin.WithClock(clk))
			require.NoError(t, err)

			in := importedAda()
			in.CreatedAt, in.UpdatedAt = tc.created, tc.updated

			_, err = im.Import(actorCtx(t), in)
			if err == nil {
				clk.Advance(time.Minute)
				_, err = im.Import(actorCtx(t), in)
			}

			tc.assert(t, got, err)
		})
	}
}
