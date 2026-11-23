package admin_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

var errStorage = errors.New("connection reset by peer")

// reasons lists every administration reason; a storage failure matches none.
var reasons = []error{admin.ErrNotFound, admin.ErrAlreadyExists, admin.ErrStillAssigned,
	admin.ErrStaleUpdate, admin.ErrUnknownPrivilege, admin.ErrInvalidInput, admin.ErrNoActor}

func TestNewUsers(t *testing.T) {
	t.Parallel()

	var nilStore *MockUserStore

	type testCase struct {
		name   string
		store  func(t *testing.T) admin.UserStore
		opts   []admin.UsersOption
		assert func(t *testing.T, u *admin.Users, err error)
	}

	store := func(t *testing.T) admin.UserStore { return NewMockUserStore(gomock.NewController(t)) }
	refused := func(t *testing.T, u *admin.Users, err error) {
		assert.ErrorIs(t, err, admin.ErrConfig)
		assert.Nil(t, u)
	}

	cases := []testCase{
		{name: "store only", store: store, assert: func(t *testing.T, u *admin.Users, err error) {
			require.NoError(t, err)
			assert.NotNil(t, u)
		}},
		{name: "nil store", store: func(*testing.T) admin.UserStore { return nil }, assert: refused},
		{name: "typed nil store", store: func(*testing.T) admin.UserStore { return nilStore }, assert: refused},
		{name: "default above maximum", store: store, opts: []admin.UsersOption{admin.WithPageSize(600, 500)}, assert: refused},
		{name: "default zero", store: store, opts: []admin.UsersOption{admin.WithPageSize(0, 500)}, assert: refused},
		{name: "maximum zero", store: store, opts: []admin.UsersOption{admin.WithPageSize(50, 0)}, assert: refused},
		{name: "default negative", store: store, opts: []admin.UsersOption{admin.WithPageSize(-1, 500)}, assert: refused},
		{name: "consumer page sizes", store: store, opts: []admin.UsersOption{admin.WithPageSize(50, 1000)},
			assert: func(t *testing.T, _ *admin.Users, err error) { require.NoError(t, err) }},
		{name: "attribute name bound zero", store: store, opts: []admin.UsersOption{admin.WithAttributeLimits(0, 10, 10)}, assert: refused},
		{name: "attribute value bound negative", store: store, opts: []admin.UsersOption{admin.WithAttributeLimits(10, -1, 10)}, assert: refused},
		{name: "attribute count zero", store: store, opts: []admin.UsersOption{admin.WithAttributeLimits(10, 10, 0)}, assert: refused},
		{name: "nil encoder", store: store, opts: []admin.UsersOption{admin.WithPasswordEncoder(nil)}, assert: refused},
		{name: "nil policy", store: store, opts: []admin.UsersOption{admin.WithPasswordPolicy(nil)}, assert: refused},
		{name: "nil clock", store: store, opts: []admin.UsersOption{admin.WithClock(nil)}, assert: refused},
		{name: "nil generator", store: store, opts: []admin.UsersOption{admin.WithIDGenerator(nil)}, assert: refused},
		{name: "nil option", store: store, opts: []admin.UsersOption{nil},
			assert: func(t *testing.T, _ *admin.Users, err error) { require.NoError(t, err) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, err := admin.NewUsers(tc.store(t), tc.opts...)
			tc.assert(t, u, err)
		})
	}
}

func TestUsers_RefusesWithoutActor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		call func(u *admin.Users, ctx context.Context) error
	}

	cases := []testCase{
		{"create", func(u *admin.Users, ctx context.Context) error {
			_, err := u.Create(ctx, admin.NewUser{Username: "ada"})
			return err
		}},
		{"update", func(u *admin.Users, ctx context.Context) error {
			name := "Ada"
			_, err := u.Update(ctx, "u-1", 1, admin.UserChange{Name: &name})
			return err
		}},
		{"deactivate", func(u *admin.Users, ctx context.Context) error {
			_, err := u.Deactivate(ctx, "u-1", 1)
			return err
		}},
		{"reactivate", func(u *admin.Users, ctx context.Context) error {
			_, err := u.Reactivate(ctx, "u-1", 1)
			return err
		}},
		{"delete", func(u *admin.Users, ctx context.Context) error {
			return u.Delete(ctx, "u-1", 1)
		}},
		{"set password", func(u *admin.Users, ctx context.Context) error {
			_, err := u.SetPassword(ctx, "u-1", 1, []byte("correct horse battery staple"))
			return err
		}},
	}

	ctxs := map[string]func(t *testing.T) context.Context{
		"no principal":      func(t *testing.T) context.Context { return t.Context() },
		"blank system name": func(t *testing.T) context.Context { return admin.WithSystemActor(t.Context(), " ") },
	}

	for _, tc := range cases {
		for cname, mk := range ctxs {
			t.Run(tc.name+"/"+cname, func(t *testing.T) {
				t.Parallel()
				// No expectation is set: any store call fails the test.
				u := newUsers(t, NewMockUserStore(gomock.NewController(t)))
				assert.ErrorIs(t, tc.call(u, mk(t)), admin.ErrNoActor)
			})
		}
	}
}

func TestUsers_AcceptsSystemActor(t *testing.T) {
	t.Parallel()

	store := NewMockUserStore(gomock.NewController(t))
	store.EXPECT().SetActive(gomock.Any(), identity.UserID("u-1"), int64(3), false).
		Return(admin.User{ID: "u-1", Version: 4}, true, nil)

	got, err := newUsers(t, store).Deactivate(admin.WithSystemActor(t.Context(), "sync"), "u-1", 3)
	require.NoError(t, err)
	assert.Equal(t, int64(4), got.Version)
}

func TestUsers_List(t *testing.T) {
	t.Parallel()

	yes := true

	type testCase struct {
		name   string
		opts   []admin.UsersOption
		filter admin.UserFilter
		setup  func(s *MockUserStore)
		assert func(t *testing.T, page admin.UserPage, err error)
	}

	invalid := func(t *testing.T, _ admin.UserPage, err error) { assert.ErrorIs(t, err, admin.ErrInvalidInput) }
	ok := func(t *testing.T, _ admin.UserPage, err error) { assert.NoError(t, err) }
	empty := func(s *MockUserStore, q admin.UserQuery) {
		s.EXPECT().ListUsers(gomock.Any(), q).Return(nil, nil)
	}

	cases := []testCase{
		{
			name:   "page size zero is the default",
			setup:  func(s *MockUserStore) { empty(s, admin.UserQuery{Limit: 50}) },
			assert: ok,
		},
		{
			name:   "maximum page",
			filter: admin.UserFilter{PageSize: 500},
			setup:  func(s *MockUserStore) { empty(s, admin.UserQuery{Limit: 500}) },
			assert: ok,
		},
		{name: "above the maximum", filter: admin.UserFilter{PageSize: 501}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "negative", filter: admin.UserFilter{PageSize: -1}, setup: func(*MockUserStore) {}, assert: invalid},
		{
			name:   "consumer maximum",
			opts:   []admin.UsersOption{admin.WithPageSize(50, 1000)},
			filter: admin.UserFilter{PageSize: 800},
			setup:  func(s *MockUserStore) { empty(s, admin.UserQuery{Limit: 800}) },
			assert: ok,
		},
		{
			name:   "consumer default",
			opts:   []admin.UsersOption{admin.WithPageSize(20, 100)},
			setup:  func(s *MockUserStore) { empty(s, admin.UserQuery{Limit: 20}) },
			assert: ok,
		},
		{
			name:   "consumer maximum still bounds",
			opts:   []admin.UsersOption{admin.WithPageSize(20, 100)},
			filter: admin.UserFilter{PageSize: 101},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{name: "malformed cursor", filter: admin.UserFilter{Cursor: "%%%"}, setup: func(*MockUserStore) {}, assert: invalid},
		{
			name: "filters reach the store",
			filter: admin.UserFilter{Search: "a_b", Active: &yes, Role: "sales",
				Attribute: &admin.AttributeMatch{Name: "job_title", Value: "Manager"}, PageSize: 10},
			setup: func(s *MockUserStore) {
				empty(s, admin.UserQuery{Search: "a_b", Active: &yes, Role: "sales",
					Attribute: &admin.AttributeMatch{Name: "job_title", Value: "Manager"}, Limit: 10})
			},
			assert: ok,
		},
		{
			name:   "search at the bound",
			filter: admin.UserFilter{Search: strings.Repeat("a", admin.MaxSearchBytes)},
			setup: func(s *MockUserStore) {
				empty(s, admin.UserQuery{Search: strings.Repeat("a", admin.MaxSearchBytes), Limit: 50})
			},
			assert: ok,
		},
		{name: "search over the bound", filter: admin.UserFilter{Search: strings.Repeat("a", admin.MaxSearchBytes+1)}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "search with NUL", filter: admin.UserFilter{Search: "a\x00b"}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "search not UTF-8", filter: admin.UserFilter{Search: "a\xffb"}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "role over the bound", filter: admin.UserFilter{Role: strings.Repeat("r", admin.MaxSearchBytes+1)}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "attribute filter with empty name", filter: admin.UserFilter{Attribute: &admin.AttributeMatch{Value: "x"}}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "attribute filter value over the bound", filter: admin.UserFilter{Attribute: &admin.AttributeMatch{Name: "n", Value: strings.Repeat("v", 1025)}}, setup: func(*MockUserStore) {}, assert: invalid},
		{
			name:   "full page sets next",
			filter: admin.UserFilter{PageSize: 2},
			setup: func(s *MockUserStore) {
				s.EXPECT().ListUsers(gomock.Any(), admin.UserQuery{Limit: 2}).
					Return([]admin.User{{ID: "u-1", Username: "ada"}, {ID: "u-2", Username: "bob"}}, nil)
			},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.NoError(t, err)
				assert.Len(t, page.Users, 2)
				assert.Equal(t, cursorOf(1, "bob", "u-2"), page.Next)
			},
		},
		{
			name:   "partial page has no next",
			filter: admin.UserFilter{PageSize: 3},
			setup: func(s *MockUserStore) {
				s.EXPECT().ListUsers(gomock.Any(), admin.UserQuery{Limit: 3}).
					Return([]admin.User{{ID: "u-1", Username: "ada"}}, nil)
			},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.NoError(t, err)
				assert.Len(t, page.Users, 1)
				assert.Empty(t, page.Next)
			},
		},
		{
			name:   "store returning more than asked is cut to the page",
			filter: admin.UserFilter{PageSize: 1},
			setup: func(s *MockUserStore) {
				s.EXPECT().ListUsers(gomock.Any(), admin.UserQuery{Limit: 1}).
					Return([]admin.User{{ID: "u-1", Username: "ada"}, {ID: "u-2", Username: "bob"}}, nil)
			},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.NoError(t, err)
				require.Len(t, page.Users, 1)
				assert.Equal(t, cursorOf(1, "ada", "u-1"), page.Next)
			},
		},
		{
			name: "storage failure matches no reason",
			setup: func(s *MockUserStore) {
				s.EXPECT().ListUsers(gomock.Any(), gomock.Any()).Return(nil, errStorage)
			},
			assert: func(t *testing.T, _ admin.UserPage, err error) {
				assert.ErrorIs(t, err, errStorage)
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockUserStore(gomock.NewController(t))
			tc.setup(store)

			page, err := newUsers(t, store, tc.opts...).List(t.Context(), tc.filter)
			tc.assert(t, page, err)
		})
	}
}

func TestUsers_Get(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		id     identity.UserID
		setup  func(s *MockUserStore)
		assert func(t *testing.T, u admin.User, err error)
	}

	cases := []testCase{
		{
			name: "found",
			id:   "u-1",
			setup: func(s *MockUserStore) {
				s.EXPECT().GetUser(gomock.Any(), identity.UserID("u-1")).Return(admin.User{ID: "u-1", Username: "ada"}, nil)
			},
			assert: func(t *testing.T, u admin.User, err error) {
				require.NoError(t, err)
				assert.Equal(t, "ada", u.Username)
			},
		},
		{
			name:  "blank identifier",
			id:    " ",
			setup: func(*MockUserStore) {},
			assert: func(t *testing.T, _ admin.User, err error) {
				assert.ErrorIs(t, err, admin.ErrInvalidInput)
			},
		},
		{
			name: "not found passes through",
			id:   "u-1",
			setup: func(s *MockUserStore) {
				s.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(admin.User{}, admin.ErrNotFound)
			},
			assert: func(t *testing.T, _ admin.User, err error) {
				assert.ErrorIs(t, err, admin.ErrNotFound)
			},
		},
		{
			name: "storage failure matches no reason",
			id:   "u-1",
			setup: func(s *MockUserStore) {
				s.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(admin.User{}, errStorage)
			},
			assert: func(t *testing.T, _ admin.User, err error) {
				assert.ErrorIs(t, err, errStorage)
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockUserStore(gomock.NewController(t))
			tc.setup(store)

			u, err := newUsers(t, store).Get(t.Context(), tc.id)
			tc.assert(t, u, err)
		})
	}
}

func TestUsers_Create(t *testing.T) {
	t.Parallel()

	uid := id.MustParse("0192f5a0-0000-7000-8000-000000000001")
	wantID := identity.UserID(uid.String())

	manyAttrs := func(n int) map[string]string {
		m := make(map[string]string, n)
		for i := range n {
			m[strings.Repeat("k", 1)+string(rune('A'+i/26))+string(rune('a'+i%26))] = "v"
		}
		return m
	}

	type testCase struct {
		name   string
		ctx    func(t *testing.T) context.Context
		opts   func(t *testing.T) []admin.UsersOption
		in     admin.NewUser
		setup  func(s *MockUserStore)
		assert func(t *testing.T, u admin.User, err error)
	}

	generator := func(t *testing.T) []admin.UsersOption {
		return []admin.UsersOption{admin.WithIDGenerator(fixedIDs(t, uid))}
	}
	invalid := func(t *testing.T, _ admin.User, err error) { assert.ErrorIs(t, err, admin.ErrInvalidInput) }
	good := admin.NewUser{Username: "ada", Name: "Ada", Email: "ada@example.com",
		Attributes: map[string]string{"phone": "+62 21 555"}}
	withUsername := func(s string) admin.NewUser { n := good; n.Username = s; return n }

	cases := []testCase{
		{
			name: "creates with a generated identifier",
			in:   good,
			setup: func(s *MockUserStore) {
				want := good
				want.ID = wantID
				s.EXPECT().CreateUser(gomock.Any(), want).Return(admin.User{ID: wantID, Username: "ada", Version: 1}, nil)
			},
			assert: func(t *testing.T, u admin.User, err error) {
				require.NoError(t, err)
				assert.Equal(t, wantID, u.ID)
			},
		},
		{
			name: "caller supplied identifier is replaced",
			in:   func() admin.NewUser { n := good; n.ID = "chosen-by-caller"; return n }(),
			setup: func(s *MockUserStore) {
				want := good
				want.ID = wantID
				s.EXPECT().CreateUser(gomock.Any(), want).Return(admin.User{ID: wantID}, nil)
			},
			assert: func(t *testing.T, _ admin.User, err error) { require.NoError(t, err) },
		},
		{
			name: "no email is allowed",
			in:   admin.NewUser{Username: "ada"},
			setup: func(s *MockUserStore) {
				s.EXPECT().CreateUser(gomock.Any(), admin.NewUser{ID: wantID, Username: "ada"}).Return(admin.User{ID: wantID}, nil)
			},
			assert: func(t *testing.T, _ admin.User, err error) { require.NoError(t, err) },
		},
		{
			name: "system actor",
			ctx:  func(t *testing.T) context.Context { return admin.WithSystemActor(t.Context(), "sync") },
			in:   admin.NewUser{Username: "ada"},
			setup: func(s *MockUserStore) {
				s.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(admin.User{ID: wantID}, nil)
			},
			assert: func(t *testing.T, _ admin.User, err error) { require.NoError(t, err) },
		},
		{
			name:   "no actor",
			ctx:    func(t *testing.T) context.Context { return t.Context() },
			in:     good,
			setup:  func(*MockUserStore) {},
			assert: func(t *testing.T, _ admin.User, err error) { assert.ErrorIs(t, err, admin.ErrNoActor) },
		},
		{name: "blank username", in: withUsername("  "), setup: func(*MockUserStore) {}, assert: invalid},
		{name: "username with surrounding space", in: withUsername(" ada"), setup: func(*MockUserStore) {}, assert: invalid},
		{name: "username with trailing space", in: withUsername("ada\t"), setup: func(*MockUserStore) {}, assert: invalid},
		{name: "empty username", in: withUsername(""), setup: func(*MockUserStore) {}, assert: invalid},
		{name: "username with control character", in: withUsername("a\nb"), setup: func(*MockUserStore) {}, assert: invalid},
		{name: "username not UTF-8", in: withUsername("a\xffb"), setup: func(*MockUserStore) {}, assert: invalid},
		{name: "username over the bound", in: withUsername(strings.Repeat("a", admin.MaxTextBytes+1)), setup: func(*MockUserStore) {}, assert: invalid},
		{
			name:   "email with control character",
			in:     admin.NewUser{Username: "ada", Email: "ada@exam\x00ple.com"},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name:   "email over the bound",
			in:     admin.NewUser{Username: "ada", Email: strings.Repeat("a", admin.MaxTextBytes+1) + "@example.com"},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name:   "blank email",
			in:     admin.NewUser{Username: "ada", Email: "   "},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name:   "verification time without an email",
			in:     admin.NewUser{Username: "ada", EmailVerifiedAt: testNow},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name:   "display name with NUL",
			in:     admin.NewUser{Username: "ada", Name: "A\x00da"},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name: "attributes at the limit",
			in:   admin.NewUser{Username: "ada", Attributes: manyAttrs(64)},
			setup: func(s *MockUserStore) {
				s.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(admin.User{ID: wantID}, nil)
			},
			assert: func(t *testing.T, _ admin.User, err error) { require.NoError(t, err) },
		},
		{
			name:   "too many attributes",
			in:     admin.NewUser{Username: "ada", Attributes: manyAttrs(65)},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name:   "attribute name empty",
			in:     admin.NewUser{Username: "ada", Attributes: map[string]string{"": "v"}},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name:   "attribute name over 64 bytes",
			in:     admin.NewUser{Username: "ada", Attributes: map[string]string{strings.Repeat("n", 65): "v"}},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name: "attribute name and value at their bounds",
			in:   admin.NewUser{Username: "ada", Attributes: map[string]string{strings.Repeat("n", 64): strings.Repeat("v", 1024)}},
			setup: func(s *MockUserStore) {
				s.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(admin.User{ID: wantID}, nil)
			},
			assert: func(t *testing.T, _ admin.User, err error) { require.NoError(t, err) },
		},
		{
			name:   "attribute value over 1024 bytes",
			in:     admin.NewUser{Username: "ada", Attributes: map[string]string{"n": strings.Repeat("v", 1025)}},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name:   "attribute value with NUL",
			in:     admin.NewUser{Username: "ada", Attributes: map[string]string{"n": "a\x00b"}},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name: "consumer attribute limits",
			opts: func(t *testing.T) []admin.UsersOption {
				return append(generator(t), admin.WithAttributeLimits(2, 3, 1))
			},
			in:     admin.NewUser{Username: "ada", Attributes: map[string]string{"abc": "v"}},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name:   "organization without identifier",
			in:     admin.NewUser{Username: "ada", Organization: &identity.Organization{}},
			setup:  func(*MockUserStore) {},
			assert: invalid,
		},
		{
			name: "identifier generator fails",
			opts: func(t *testing.T) []admin.UsersOption {
				g := NewMockGenerator(gomock.NewController(t))
				g.EXPECT().NewID().Return(id.Nil, errStorage)
				return []admin.UsersOption{admin.WithIDGenerator(g)}
			},
			in:    good,
			setup: func(*MockUserStore) {},
			assert: func(t *testing.T, _ admin.User, err error) {
				assert.ErrorIs(t, err, errStorage)
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
			},
		},
		{
			name: "identifier generator returns the zero identifier",
			opts: func(t *testing.T) []admin.UsersOption {
				g := NewMockGenerator(gomock.NewController(t))
				g.EXPECT().NewID().Return(id.Nil, nil)
				return []admin.UsersOption{admin.WithIDGenerator(g)}
			},
			in:    good,
			setup: func(*MockUserStore) {},
			assert: func(t *testing.T, _ admin.User, err error) {
				require.Error(t, err)
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
			},
		},
		{
			name: "taken username passes through with its field and no value",
			in:   good,
			setup: func(s *MockUserStore) {
				s.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(admin.User{}, admin.AlreadyExistsError{Field: admin.FieldUsername})
			},
			assert: func(t *testing.T, _ admin.User, err error) {
				var ae admin.AlreadyExistsError
				require.ErrorAs(t, err, &ae)
				assert.Equal(t, admin.FieldUsername, ae.Field)
				assert.ErrorIs(t, err, admin.ErrAlreadyExists)
				assert.NotContains(t, err.Error(), "ada")
			},
		},
		{
			name: "storage failure matches no reason and leaks no input",
			in:   good,
			setup: func(s *MockUserStore) {
				s.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(admin.User{}, errStorage)
			},
			assert: func(t *testing.T, _ admin.User, err error) {
				assert.ErrorIs(t, err, errStorage)
				assert.NotContains(t, err.Error(), "ada")
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := actorCtx(t)
			if tc.ctx != nil {
				ctx = tc.ctx(t)
			}

			opts := generator(t)
			if tc.opts != nil {
				opts = tc.opts(t)
			}

			store := NewMockUserStore(gomock.NewController(t))
			tc.setup(store)

			u, err := newUsers(t, store, opts...).Create(ctx, tc.in)
			tc.assert(t, u, err)
		})
	}
}

func TestUsers_Update(t *testing.T) {
	t.Parallel()

	name := "Ada L."
	email := "ada@example.com"
	longName := strings.Repeat("n", admin.MaxTextBytes+1)
	badEmail := "a\x01@example.com"
	blankEmail := "  "
	noEmail := ""
	verified := testNow
	var noOrg *identity.Organization

	type testCase struct {
		name    string
		id      identity.UserID
		version int64
		change  admin.UserChange
		setup   func(s *MockUserStore)
		assert  func(t *testing.T, u admin.User, err error)
	}

	invalid := func(t *testing.T, _ admin.User, err error) { assert.ErrorIs(t, err, admin.ErrInvalidInput) }

	cases := []testCase{
		{
			name: "named fields reach the store", id: "u-1", version: 3,
			change: admin.UserChange{Name: &name, Email: &email, EmailVerifiedAt: &verified,
				Attributes: map[string]string{"a": "b"}, Organization: &noOrg},
			setup: func(s *MockUserStore) {
				s.EXPECT().UpdateUser(gomock.Any(), identity.UserID("u-1"), int64(3),
					admin.UserChange{Name: &name, Email: &email, EmailVerifiedAt: &verified,
						Attributes: map[string]string{"a": "b"}, Organization: &noOrg}).
					Return(admin.User{ID: "u-1", Version: 4}, nil)
			},
			assert: func(t *testing.T, u admin.User, err error) {
				require.NoError(t, err)
				assert.Equal(t, int64(4), u.Version)
			},
		},
		{
			name: "clearing the email and the attributes is allowed", id: "u-1", version: 1,
			change: func() admin.UserChange { e := ""; return admin.UserChange{Email: &e, Attributes: map[string]string{}} }(),
			setup: func(s *MockUserStore) {
				s.EXPECT().UpdateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(admin.User{}, nil)
			},
			assert: func(t *testing.T, _ admin.User, err error) { require.NoError(t, err) },
		},
		{name: "nothing named", id: "u-1", version: 1, change: admin.UserChange{}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "version zero", id: "u-1", version: 0, change: admin.UserChange{Name: &name}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "version negative", id: "u-1", version: -4, change: admin.UserChange{Name: &name}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "blank identifier", id: "", version: 1, change: admin.UserChange{Name: &name}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "name over the bound", id: "u-1", version: 1, change: admin.UserChange{Name: &longName}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "email with control character", id: "u-1", version: 1, change: admin.UserChange{Email: &badEmail}, setup: func(*MockUserStore) {}, assert: invalid},
		{name: "blank email", id: "u-1", version: 1, change: admin.UserChange{Email: &blankEmail}, setup: func(*MockUserStore) {}, assert: invalid},
		{
			name: "verification time with the email cleared", id: "u-1", version: 1,
			change: admin.UserChange{Email: &noEmail, EmailVerifiedAt: &verified},
			setup:  func(*MockUserStore) {}, assert: invalid,
		},
		{
			name: "too many attributes", id: "u-1", version: 1,
			change: admin.UserChange{Attributes: func() map[string]string {
				m := map[string]string{}
				for i := range 65 {
					m[strings.Repeat("k", i+1)] = "v"
				}
				return m
			}()},
			setup: func(*MockUserStore) {}, assert: invalid,
		},
		{
			name: "stale update passes through", id: "u-1", version: 1, change: admin.UserChange{Name: &name},
			setup: func(s *MockUserStore) {
				s.EXPECT().UpdateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(admin.User{}, admin.ErrStaleUpdate)
			},
			assert: func(t *testing.T, _ admin.User, err error) { assert.ErrorIs(t, err, admin.ErrStaleUpdate) },
		},
		{
			name: "not found passes through", id: "u-1", version: 1, change: admin.UserChange{Name: &name},
			setup: func(s *MockUserStore) {
				s.EXPECT().UpdateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(admin.User{}, admin.ErrNotFound)
			},
			assert: func(t *testing.T, _ admin.User, err error) { assert.ErrorIs(t, err, admin.ErrNotFound) },
		},
		{
			name: "taken email passes through", id: "u-1", version: 1, change: admin.UserChange{Email: &email},
			setup: func(s *MockUserStore) {
				s.EXPECT().UpdateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(admin.User{}, admin.AlreadyExistsError{Field: admin.FieldEmail})
			},
			assert: func(t *testing.T, _ admin.User, err error) {
				assert.ErrorIs(t, err, admin.ErrAlreadyExists)
				assert.NotContains(t, err.Error(), "ada@example.com")
			},
		},
		{
			name: "storage failure matches no reason", id: "u-1", version: 1, change: admin.UserChange{Name: &name},
			setup: func(s *MockUserStore) {
				s.EXPECT().UpdateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(admin.User{}, errStorage)
			},
			assert: func(t *testing.T, _ admin.User, err error) {
				assert.ErrorIs(t, err, errStorage)
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockUserStore(gomock.NewController(t))
			tc.setup(store)

			u, err := newUsers(t, store).Update(actorCtx(t), tc.id, tc.version, tc.change)
			tc.assert(t, u, err)
		})
	}
}

func TestUsers_ActiveAndDelete(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		id      identity.UserID
		version int64
		setup   func(s *MockUserStore)
		call    func(u *admin.Users, ctx context.Context, id identity.UserID, v int64) error
		assert  func(t *testing.T, err error)
	}

	deactivate := func(u *admin.Users, ctx context.Context, id identity.UserID, v int64) error {
		_, err := u.Deactivate(ctx, id, v)
		return err
	}
	reactivate := func(u *admin.Users, ctx context.Context, id identity.UserID, v int64) error {
		_, err := u.Reactivate(ctx, id, v)
		return err
	}
	del := func(u *admin.Users, ctx context.Context, id identity.UserID, v int64) error {
		return u.Delete(ctx, id, v)
	}
	nothing := func(*MockUserStore) {}
	invalid := func(t *testing.T, err error) { assert.ErrorIs(t, err, admin.ErrInvalidInput) }

	cases := []testCase{
		{
			name: "deactivate", id: "u-1", version: 2, call: deactivate,
			setup: func(s *MockUserStore) {
				s.EXPECT().SetActive(gomock.Any(), identity.UserID("u-1"), int64(2), false).Return(admin.User{}, true, nil)
			},
			assert: func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			name: "deactivating an inactive user succeeds", id: "u-1", version: 2, call: deactivate,
			setup: func(s *MockUserStore) {
				s.EXPECT().SetActive(gomock.Any(), gomock.Any(), gomock.Any(), false).Return(admin.User{}, false, nil)
			},
			assert: func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			name: "reactivate", id: "u-1", version: 2, call: reactivate,
			setup: func(s *MockUserStore) {
				s.EXPECT().SetActive(gomock.Any(), identity.UserID("u-1"), int64(2), true).Return(admin.User{}, true, nil)
			},
			assert: func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			name: "delete", id: "u-1", version: 2, call: del,
			setup: func(s *MockUserStore) {
				s.EXPECT().DeleteUser(gomock.Any(), identity.UserID("u-1"), int64(2)).Return(nil)
			},
			assert: func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			name: "delete of a deleted user", id: "u-1", version: 2, call: del,
			setup: func(s *MockUserStore) {
				s.EXPECT().DeleteUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(admin.ErrNotFound)
			},
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, admin.ErrNotFound) },
		},
		{
			name: "stale deactivate", id: "u-1", version: 2, call: deactivate,
			setup: func(s *MockUserStore) {
				s.EXPECT().SetActive(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(admin.User{}, false, admin.ErrStaleUpdate)
			},
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, admin.ErrStaleUpdate) },
		},
		{name: "deactivate with version zero", id: "u-1", version: 0, call: deactivate, setup: nothing, assert: invalid},
		{name: "reactivate with blank identifier", id: "", version: 1, call: reactivate, setup: nothing, assert: invalid},
		{name: "delete with negative version", id: "u-1", version: -1, call: del, setup: nothing, assert: invalid},
		{
			name: "storage failure on delete matches no reason", id: "u-1", version: 2, call: del,
			setup: func(s *MockUserStore) {
				s.EXPECT().DeleteUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(errStorage)
			},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, errStorage)
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockUserStore(gomock.NewController(t))
			tc.setup(store)

			tc.assert(t, tc.call(newUsers(t, store), actorCtx(t), tc.id, tc.version))
		})
	}
}

// TestUsers_InputIsCopied pins that the store receives a copy of the caller's
// attributes and attribute filter, so a caller changing them after the call
// was validated cannot change what is written or searched.
func TestUsers_InputIsCopied(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		call func(t *testing.T, store *MockUserStore, u *admin.Users)
	}

	cases := []testCase{
		{
			name: "create",
			call: func(t *testing.T, store *MockUserStore, u *admin.Users) {
				attrs := map[string]string{"phone": "1"}
				store.EXPECT().CreateUser(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, nu admin.NewUser) (admin.User, error) {
						attrs["phone"] = strings.Repeat("x", 5000)
						assert.Equal(t, map[string]string{"phone": "1"}, nu.Attributes)

						return admin.User{}, nil
					})

				_, err := u.Create(actorCtx(t), admin.NewUser{Username: "ada", Attributes: attrs})
				require.NoError(t, err)
			},
		},
		{
			name: "update",
			call: func(t *testing.T, store *MockUserStore, u *admin.Users) {
				attrs := map[string]string{"phone": "1"}
				store.EXPECT().UpdateUser(gomock.Any(), identity.UserID("u-1"), int64(1), gomock.Any()).DoAndReturn(
					func(_ context.Context, _ identity.UserID, _ int64, c admin.UserChange) (admin.User, error) {
						attrs["phone"] = strings.Repeat("x", 5000)
						assert.Equal(t, map[string]string{"phone": "1"}, c.Attributes)

						return admin.User{}, nil
					})

				_, err := u.Update(actorCtx(t), "u-1", 1, admin.UserChange{Attributes: attrs})
				require.NoError(t, err)
			},
		},
		{
			name: "list",
			call: func(t *testing.T, store *MockUserStore, u *admin.Users) {
				match := &admin.AttributeMatch{Name: "job_title", Value: "Manager"}
				store.EXPECT().ListUsers(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, q admin.UserQuery) ([]admin.User, error) {
						match.Value = strings.Repeat("x", 5000)
						assert.Equal(t, &admin.AttributeMatch{Name: "job_title", Value: "Manager"}, q.Attribute)

						return nil, nil
					})

				_, err := u.List(t.Context(), admin.UserFilter{Attribute: match})
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockUserStore(gomock.NewController(t))
			tc.call(t, store, newUsers(t, store))
		})
	}
}

// TestUsers_UpdateEmailClearsVerification pins that a new or cleared email
// never inherits the old address's verification: a change that names the
// email but no verification time reaches the store with the time cleared.
func TestUsers_UpdateEmailClearsVerification(t *testing.T) {
	t.Parallel()

	email := "new@example.com"
	noEmail := ""
	name := "Ada"
	verified := testNow

	type testCase struct {
		name   string
		change admin.UserChange
		assert func(t *testing.T, got admin.UserChange)
	}

	cleared := func(t *testing.T, got admin.UserChange) {
		require.NotNil(t, got.EmailVerifiedAt)
		assert.True(t, got.EmailVerifiedAt.IsZero())
	}

	cases := []testCase{
		{name: "email set without a verification time", change: admin.UserChange{Email: &email}, assert: cleared},
		{name: "email cleared", change: admin.UserChange{Email: &noEmail}, assert: cleared},
		{
			name:   "email set with a verification time keeps it",
			change: admin.UserChange{Email: &email, EmailVerifiedAt: &verified},
			assert: func(t *testing.T, got admin.UserChange) {
				require.NotNil(t, got.EmailVerifiedAt)
				assert.True(t, got.EmailVerifiedAt.Equal(testNow))
			},
		},
		{
			name:   "email not named leaves the verification alone",
			change: admin.UserChange{Name: &name},
			assert: func(t *testing.T, got admin.UserChange) { assert.Nil(t, got.EmailVerifiedAt) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got admin.UserChange
			store := NewMockUserStore(gomock.NewController(t))
			store.EXPECT().UpdateUser(gomock.Any(), identity.UserID("u-1"), int64(1), gomock.Any()).DoAndReturn(
				func(_ context.Context, _ identity.UserID, _ int64, c admin.UserChange) (admin.User, error) {
					got = c

					return admin.User{}, nil
				})

			_, err := newUsers(t, store).Update(actorCtx(t), "u-1", 1, tc.change)
			require.NoError(t, err)
			tc.assert(t, got)
		})
	}
}
