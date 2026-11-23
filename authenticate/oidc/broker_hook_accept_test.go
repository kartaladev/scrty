package oidc_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// hookToken is the upstream access token of every accept-path row.
const hookToken = "at-secret"

// hookDirectory is the user store behind an accept-path row: a mocked
// UserLoader answers from it, and an apply step may change it.
type hookDirectory struct {
	mu    sync.Mutex
	users map[identity.UserID]identity.Details
	// loadsAs makes a reference load as another user's details.
	loadsAs map[identity.UserID]identity.UserID
	// fault, when set, is the loader's answer for every reference.
	fault error
}

func newHookDirectory(users ...identity.Details) *hookDirectory {
	d := &hookDirectory{users: map[identity.UserID]identity.Details{}, loadsAs: map[identity.UserID]identity.UserID{}}
	for _, u := range users {
		d.users[u.ID] = u
	}
	return d
}

// activeUser returns the details of an active user named after its reference.
func activeUser(ref identity.UserID) identity.Details {
	return identity.Details{ID: ref, Username: "name-" + string(ref), Active: true}
}

func (d *hookDirectory) load(_ context.Context, ref identity.UserID) (*identity.Details, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fault != nil {
		return nil, d.fault
	}
	if as, ok := d.loadsAs[ref]; ok {
		ref = as
	}
	u, ok := d.users[ref]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	return &u, nil
}

func (d *hookDirectory) disable(ref identity.UserID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	u := d.users[ref]
	u.Active = false
	d.users[ref] = u
}

// remove deletes ref, as an apply step that deletes its user does.
func (d *hookDirectory) remove(ref identity.UserID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.users, ref)
}

func (d *hookDirectory) loader(ctrl *gomock.Controller) *MockUserLoader {
	l := NewMockUserLoader(ctrl)
	l.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(d.load).AnyTimes()
	return l
}

// applyRecord records every apply step that ran: the user it wrote, and the
// link of the identity it saw when it ran.
type applyRecord struct {
	mu    sync.Mutex
	calls []applyCall
}

type applyCall struct {
	target identity.UserID
	link   *oidc.Link // the identity's link when the step ran; nil when none
}

// step returns an apply step writing target, which records itself, with the
// identity's link in links when links is not nil, and then runs then (nil
// means succeed).
func (r *applyRecord) step(links oidc.LinkStore, ext oidc.ExternalIdentity, target identity.UserID,
	then func(ctx context.Context) error,
) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		var l *oidc.Link
		if links != nil {
			if found, err := links.FindByExternal(ctx, ext.Provider, ext.Issuer, ext.Subject); err == nil {
				l = found
			}
		}
		r.mu.Lock()
		r.calls = append(r.calls, applyCall{target: target, link: l})
		r.mu.Unlock()
		if then != nil {
			return then(ctx)
		}
		return nil
	}
}

func (r *applyRecord) all() []applyCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// corpIdentity returns the corp identity with the given subject.
func corpIdentity(subject string) oidc.ExternalIdentity {
	ext := brokerCorpIdentity()
	ext.Subject = subject
	return ext
}

// corpLink returns a link from the corp identity subject to user.
func corpLink(subject string, user identity.UserID) oidc.Link {
	return oidc.Link{
		Provider: "corp", Issuer: brokerCorpIssuer, Subject: subject,
		UserID: user, Username: "name-" + string(user), Email: "alice@corp.example",
	}
}

// findCorp returns the corp link of subject, or nil.
func findCorp(t *testing.T, links oidc.LinkStore, subject string) *oidc.Link {
	t.Helper()
	l, err := links.FindByExternal(t.Context(), "corp", brokerCorpIssuer, subject)
	if errors.Is(err, oidc.ErrLinkNotFound) {
		return nil
	}
	require.NoError(t, err)
	return l
}

// assertBrokerFailure asserts err is a broker failure: neither an
// authentication failure nor a refusal outcome.
func assertBrokerFailure(t *testing.T, p *identity.Principal, err error) {
	t.Helper()
	require.Error(t, err)
	assert.Nil(t, p)
	assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
	assert.NotErrorIs(t, err, oidc.ErrNoLinkedAccount)
	assert.NotErrorIs(t, err, oidc.ErrProvisioningRefused)
}

// assertScrubbed asserts text names no subject, email, user reference or
// token of the row.
func assertScrubbed(t *testing.T, text string, refs ...string) {
	t.Helper()
	for _, s := range append([]string{"alice@corp.example", "alice@", "s-1", hookToken}, refs...) {
		assert.NotContains(t, text, s)
	}
}

func TestBroker_HookChecksBeforeWrite(t *testing.T) {
	t.Parallel()

	ext := corpIdentity("s-1")

	type env struct {
		links   *oidc.MemoryLinkStore
		applies *applyRecord
		logs    string
	}
	type testCase struct {
		name      string
		ctx       func(ctx context.Context) context.Context
		link      *oidc.Link // the identity's link before the login; nil means none
		decide    identity.UserID
		provision bool
		prepare   func(d *hookDirectory)
		assert    func(t *testing.T, e env, p *identity.Principal, err error)
	}

	refusedUnlinked := func(t *testing.T, e env, p *identity.Principal, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
		assert.Nil(t, p)
		assert.Empty(t, e.applies.all(), "a refused decision never runs its apply step")
		assert.Nil(t, findCorp(t, e.links, "s-1"), "a refused decision writes no link")
	}

	cases := []testCase{
		{
			name:   "a link to u-7 and a decision for u-9 is refused, the link unchanged, with one warning naming no user",
			link:   new(corpLink("s-1", "u-7")),
			decide: "u-9",
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Empty(t, e.applies.all())
				l := findCorp(t, e.links, "s-1")
				require.NotNil(t, l)
				assert.Equal(t, identity.UserID("u-7"), l.UserID)
				assert.Equal(t, 1, strings.Count(e.logs, "level=WARN"), e.logs)
				assert.Contains(t, e.logs, "provider=corp")
				assert.Contains(t, e.logs, "email_domain=corp.example")
				assertScrubbed(t, e.logs, "u-7", "u-9")
			},
		},
		{
			name:   "a decision for a missing user is refused before anything is written",
			decide: "u-404",
			assert: refusedUnlinked,
		},
		{
			name:    "a decision for a disabled user is refused before anything is written",
			decide:  "u-7",
			prepare: func(d *hookDirectory) { d.disable("u-7") },
			assert:  refusedUnlinked,
		},
		{
			name:    "a decided reference that loads as another user is refused before anything is written",
			decide:  "u-7",
			prepare: func(d *hookDirectory) { d.loadsAs["u-7"] = "u-8" },
			assert:  refusedUnlinked,
		},
		{
			name:    "a loader fault is a redacted broker failure, never a refusal, and nothing is written",
			decide:  "u-7",
			prepare: func(d *hookDirectory) { d.fault = errors.New("db down s-1 alice@corp.example u-7 " + hookToken) },
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				assertScrubbed(t, err.Error(), "u-7")
				assert.Empty(t, e.applies.all())
				assert.Nil(t, findCorp(t, e.links, "s-1"))
			},
		},
		{
			// Provisioning decisions are not accepted yet: refused before
			// anything is written, whatever the user store holds.
			name:      "a provisioning decision is a broker failure, and nothing is written",
			decide:    "u-7",
			provision: true,
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				assert.Empty(t, e.applies.all())
				assert.Nil(t, findCorp(t, e.links, "s-1"))
			},
		},
		{
			name: "a context cancelled during the checks is the context's error, and nothing is written",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			decide:  "u-7",
			prepare: func(d *hookDirectory) { d.fault = context.Canceled },
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, e.applies.all())
				assert.Nil(t, findCorp(t, e.links, "s-1"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			links := oidc.NewMemoryLinkStore()
			if tc.link != nil {
				require.NoError(t, links.Insert(t.Context(), *tc.link))
			}
			dir := newHookDirectory(activeUser("u-7"), activeUser("u-8"), activeUser("u-9"))
			if tc.prepare != nil {
				tc.prepare(dir)
			}
			applies := &applyRecord{}
			hook := func(_ context.Context, ext oidc.ExternalIdentity, _ oidc.Upstream, _ identity.UserID) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{User: tc.decide, Provision: tc.provision, Apply: applies.step(links, ext, tc.decide, nil)}, nil
			}
			var logs bytes.Buffer
			b, err := oidc.NewBroker(links, dir.loader(gomock.NewController(t)),
				oidc.WithBrokerLogger(testTextLogger(&logs)), oidc.WithBrokerSignInHook("corp", hook))
			require.NoError(t, err)

			p, err := b.BrokerUpstream(ctx, ext, oidc.NewUpstreamForTest(hookToken, "s-1", nil, nil))
			tc.assert(t, env{links: links, applies: applies, logs: logs.String()}, p, err)
		})
	}
}

func TestBroker_HookLinksThenApplies(t *testing.T) {
	t.Parallel()

	ext := corpIdentity("s-1")
	seeded := corpLink("s-1", "u-7")
	seeded.ID = id.MustParse("01926a4e-0000-7000-8000-000000000051")

	type env struct {
		links   oidc.LinkStore
		dir     *hookDirectory
		applies *applyRecord
		linked  func() []identity.UserID // the linked user the hook was handed, per call
		cancel  context.CancelFunc       // ends the login's request
		logs    *bytes.Buffer            // the broker's log, read once the login returned
	}
	type testCase struct {
		name string
		// links builds the store; nil means a memory store holding link.
		links func(t *testing.T, ctrl *gomock.Controller) oidc.LinkStore
		link  *oidc.Link
		ids   func(ctrl *gomock.Controller) oidc.BrokerOption // nil means the default generator
		// decide answers the hook; nil decides u-7 with an apply step that
		// writes u-7 and then runs then.
		decide func(e env, linked identity.UserID) oidc.SignInDecision
		then   func(e env) func(ctx context.Context) error
		assert func(t *testing.T, e env, p *identity.Principal, err error)
	}

	faultyStore := func(expect func(s *MockLinkStore, l *MockLinkLister, r *MockLinkRemover)) func(*testing.T, *gomock.Controller) oidc.LinkStore {
		return func(_ *testing.T, ctrl *gomock.Controller) oidc.LinkStore {
			s := hookLinkStore{MockLinkStore: NewMockLinkStore(ctrl), MockLinkLister: NewMockLinkLister(ctrl), MockLinkRemover: NewMockLinkRemover(ctrl)}
			expect(s.MockLinkStore, s.MockLinkLister, s.MockLinkRemover)
			return s
		}
	}
	notFound := func(s *MockLinkStore) *MockLinkStoreFindByExternalCall {
		return s.EXPECT().FindByExternal(gomock.Any(), "corp", brokerCorpIssuer, "s-1").Return(nil, oidc.ErrLinkNotFound)
	}
	leak := errors.New("db down s-1 alice@corp.example u-7 name-u-7 " + hookToken)
	storeFault := func(t *testing.T, e env, p *identity.Principal, err error) {
		t.Helper()
		assertBrokerFailure(t, p, err)
		require.ErrorIs(t, err, leak, "the fault stays reachable")
		assertScrubbed(t, err.Error(), "u-7", "name-u-7")
		assert.Empty(t, e.applies.all(), "a store fault runs no apply step")
	}

	cases := []testCase{
		{
			name: "a first sign-in stores the link with the loaded username, then applies once, and resolves to u-7",
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("u-7"), p.ID)
				l := findCorp(t, e.links, "s-1")
				require.NotNil(t, l)
				assert.Equal(t, identity.UserID("u-7"), l.UserID)
				assert.Equal(t, "name-u-7", l.Username)
				assert.Equal(t, "alice@corp.example", l.Email)
				assert.NotEqual(t, id.Nil, l.ID)
				calls := e.applies.all()
				require.Len(t, calls, 1)
				require.NotNil(t, calls[0].link, "the link exists when the apply step runs")
				assert.Equal(t, *l, *calls[0].link)
			},
		},
		{
			name: "a later sign-in inserts nothing and applies again",
			link: &seeded,
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-7"), p.ID)
				assert.Equal(t, &seeded, findCorp(t, e.links, "s-1"), "the stored link is unchanged")
				calls := e.applies.all()
				require.Len(t, calls, 1)
				assert.Equal(t, &seeded, calls[0].link)
			},
		},
		{
			name: "a decision with no apply step links and resolves",
			decide: func(_ env, _ identity.UserID) oidc.SignInDecision {
				return oidc.SignInDecision{User: "u-7"}
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-7"), p.ID)
				require.NotNil(t, findCorp(t, e.links, "s-1"))
			},
		},
		{
			name: "a failing apply step is a broker failure with fixed text, and the link stays",
			then: func(env) func(context.Context) error {
				return func(context.Context) error { return errors.New("write failed alice@corp.example s-1 " + hookToken) }
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				assert.NotContains(t, err.Error(), "write failed")
				assertScrubbed(t, err.Error())
				assert.Len(t, e.applies.all(), 1)
				l := findCorp(t, e.links, "s-1")
				require.NotNil(t, l, "the link stays for the next sign-in to re-apply")
				assert.Equal(t, identity.UserID("u-7"), l.UserID)
			},
		},
		{
			name: "an apply step stopped by a cancelled context is the context's error, and the link stays",
			then: func(e env) func(context.Context) error {
				return func(ctx context.Context) error {
					e.cancel() // the request ends while the step runs
					return ctx.Err()
				}
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				require.ErrorIs(t, err, context.Canceled)
				require.NotNil(t, findCorp(t, e.links, "s-1"))
			},
		},
		{
			name: "an apply step that disables the user is refused, and the link stays",
			then: func(e env) func(context.Context) error {
				return func(context.Context) error { e.dir.disable("u-7"); return nil }
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Len(t, e.applies.all(), 1)
				require.NotNil(t, findCorp(t, e.links, "s-1"))
			},
		},
		{
			name: "an apply step that deletes the user is refused with one warning naming no user, and the link stays",
			then: func(e env) func(context.Context) error {
				return func(context.Context) error { e.dir.remove("u-7"); return nil }
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Len(t, e.applies.all(), 1)
				require.NotNil(t, findCorp(t, e.links, "s-1"))
				logs := e.logs.String()
				assert.Equal(t, 1, strings.Count(logs, "level=WARN"), logs)
				assert.Contains(t, logs, "disappeared during the sign-in hook's apply step")
				assert.Contains(t, logs, "provider=corp")
				assert.Contains(t, logs, "email_domain=corp.example")
				assertScrubbed(t, logs, "u-7", "name-u-7")
			},
		},
		{
			name: "a loader fault on the reload after the apply step is a redacted broker failure, and the link stays",
			then: func(e env) func(context.Context) error {
				return func(context.Context) error {
					e.dir.mu.Lock()
					e.dir.fault = leak
					e.dir.mu.Unlock()
					return nil
				}
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				require.ErrorIs(t, err, leak)
				assertScrubbed(t, err.Error(), "u-7", "name-u-7")
				require.NotNil(t, findCorp(t, e.links, "s-1"))
			},
		},
		{
			// Review Focus 1: the hook finds u-9 by email but decides the
			// linked u-7. The apply step writes only the decided user.
			name: "the hook handed linked u-7 that finds u-9 by email and decides u-7 applies to u-7 only",
			link: &seeded,
			decide: func(e env, linked identity.UserID) oidc.SignInDecision {
				byEmail := identity.UserID("u-9") // the consumer's own lookup by email
				decided := byEmail
				if linked != "" {
					decided = linked
				}
				return oidc.SignInDecision{User: decided, Apply: e.applies.step(e.links, ext, decided, nil)}
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.NoError(t, err)
				assert.Equal(t, []identity.UserID{"u-7"}, e.linked())
				calls := e.applies.all()
				require.Len(t, calls, 1)
				assert.Equal(t, identity.UserID("u-7"), calls[0].target)
				assert.Equal(t, p.ID, calls[0].target, "the apply step wrote the resolved user")
				for _, c := range calls {
					assert.NotEqual(t, identity.UserID("u-9"), c.target)
				}
			},
		},
		{
			name: "a fault generating the link identifier is a broker failure, and nothing is written",
			ids: func(ctrl *gomock.Controller) oidc.BrokerOption {
				g := NewMockHandoffIDGenerator(ctrl)
				g.EXPECT().NewID().Return(id.Nil, leak)
				return oidc.WithBrokerIDGenerator(g)
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				assert.Empty(t, e.applies.all())
				assert.Nil(t, findCorp(t, e.links, "s-1"))
			},
		},
		{
			name: "a FindByExternal fault is a redacted broker failure, and the hook is not reached",
			links: faultyStore(func(s *MockLinkStore, _ *MockLinkLister, _ *MockLinkRemover) {
				s.EXPECT().FindByExternal(gomock.Any(), "corp", brokerCorpIssuer, "s-1").Return(nil, leak)
			}),
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				// No user is known yet, so only the identity and token are
				// redacted.
				assertBrokerFailure(t, p, err)
				require.ErrorIs(t, err, leak)
				assertScrubbed(t, err.Error())
				assert.Empty(t, e.linked())
			},
		},
		{
			name: "a ListByUser fault before the insert is a redacted broker failure, and nothing is written",
			links: faultyStore(func(s *MockLinkStore, l *MockLinkLister, _ *MockLinkRemover) {
				notFound(s)
				l.EXPECT().ListByUser(gomock.Any(), identity.UserID("u-7")).Return(nil, leak)
				s.EXPECT().Insert(gomock.Any(), gomock.Any()).Times(0)
			}),
			assert: storeFault,
		},
		{
			name: "an Insert fault is a redacted broker failure",
			links: faultyStore(func(s *MockLinkStore, l *MockLinkLister, _ *MockLinkRemover) {
				notFound(s)
				l.EXPECT().ListByUser(gomock.Any(), identity.UserID("u-7")).Return([]oidc.Link{}, nil)
				s.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(leak)
			}),
			assert: storeFault,
		},
		{
			name: "a fault re-reading the link after ErrLinkExists is a redacted broker failure",
			links: faultyStore(func(s *MockLinkStore, l *MockLinkLister, _ *MockLinkRemover) {
				gomock.InOrder(
					notFound(s),
					s.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(oidc.ErrLinkExists),
					s.EXPECT().FindByExternal(gomock.Any(), "corp", brokerCorpIssuer, "s-1").Return(nil, leak),
				)
				l.EXPECT().ListByUser(gomock.Any(), identity.UserID("u-7")).Return([]oidc.Link{}, nil)
			}),
			assert: storeFault,
		},
		{
			name: "a re-read that finds no link after ErrLinkExists is a lost race, refused without Apply",
			links: faultyStore(func(s *MockLinkStore, l *MockLinkLister, _ *MockLinkRemover) {
				gomock.InOrder(
					notFound(s),
					s.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(oidc.ErrLinkExists),
					s.EXPECT().FindByExternal(gomock.Any(), "corp", brokerCorpIssuer, "s-1").Return(nil, oidc.ErrLinkNotFound),
				)
				l.EXPECT().ListByUser(gomock.Any(), identity.UserID("u-7")).Return([]oidc.Link{}, nil)
			}),
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Empty(t, e.applies.all())
			},
		},
		{
			name: "a re-read that returns neither a link nor an error after ErrLinkExists is a broker failure",
			links: faultyStore(func(s *MockLinkStore, l *MockLinkLister, _ *MockLinkRemover) {
				gomock.InOrder(
					notFound(s),
					s.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(oidc.ErrLinkExists),
					s.EXPECT().FindByExternal(gomock.Any(), "corp", brokerCorpIssuer, "s-1").Return(nil, nil),
				)
				l.EXPECT().ListByUser(gomock.Any(), identity.UserID("u-7")).Return([]oidc.Link{}, nil)
			}),
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				assert.Empty(t, e.applies.all())
			},
		},
		{
			name: "a ListByUser fault on the re-check after the insert removes this link and is a redacted broker failure",
			links: faultyStore(func(s *MockLinkStore, l *MockLinkLister, r *MockLinkRemover) {
				var inserted oidc.Link
				notFound(s)
				gomock.InOrder(
					l.EXPECT().ListByUser(gomock.Any(), identity.UserID("u-7")).Return([]oidc.Link{}, nil),
					s.EXPECT().Insert(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, link oidc.Link) error {
						inserted = link
						return nil
					}),
					l.EXPECT().ListByUser(gomock.Any(), identity.UserID("u-7")).Return(nil, leak),
					r.EXPECT().DeleteLink(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, link oidc.Link) (bool, error) {
						if link != inserted {
							return false, errors.New("DeleteLink was not given the inserted link")
						}
						return true, nil
					}),
				)
				s.EXPECT().DeleteByUser(gomock.Any(), gomock.Any()).Times(0)
			}),
			assert: storeFault,
		},
		{
			name: "a DeleteLink fault undoing a duplicate link is a redacted broker failure",
			links: faultyStore(func(s *MockLinkStore, l *MockLinkLister, r *MockLinkRemover) {
				notFound(s)
				gomock.InOrder(
					l.EXPECT().ListByUser(gomock.Any(), identity.UserID("u-7")).Return([]oidc.Link{}, nil),
					s.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(nil),
					l.EXPECT().ListByUser(gomock.Any(), identity.UserID("u-7")).DoAndReturn(
						func(context.Context, identity.UserID) ([]oidc.Link, error) {
							return []oidc.Link{corpLink("s-1", "u-7"), corpLink("s-2", "u-7")}, nil
						}),
					r.EXPECT().DeleteLink(gomock.Any(), gomock.Any()).Return(false, leak),
				)
				s.EXPECT().DeleteByUser(gomock.Any(), gomock.Any()).Times(0)
			}),
			assert: storeFault,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctrl := gomock.NewController(t)

			var links oidc.LinkStore
			if tc.links != nil {
				links = tc.links(t, ctrl)
			} else {
				m := oidc.NewMemoryLinkStore()
				if tc.link != nil {
					require.NoError(t, m.Insert(t.Context(), *tc.link))
				}
				links = m
			}
			e := env{dir: newHookDirectory(activeUser("u-7"), activeUser("u-9")), applies: &applyRecord{}, cancel: cancel,
				logs: &bytes.Buffer{}}
			if tc.links == nil {
				e.links = links
			}
			var (
				mu     sync.Mutex
				linked []identity.UserID
			)
			e.linked = func() []identity.UserID {
				mu.Lock()
				defer mu.Unlock()
				return slices.Clone(linked)
			}
			hook := func(_ context.Context, _ oidc.ExternalIdentity, _ oidc.Upstream, l identity.UserID) (oidc.SignInDecision, error) {
				mu.Lock()
				linked = append(linked, l)
				mu.Unlock()
				if tc.decide != nil {
					return tc.decide(e, l), nil
				}
				var then func(context.Context) error
				if tc.then != nil {
					then = tc.then(e)
				}
				return oidc.SignInDecision{User: "u-7", Apply: e.applies.step(e.links, ext, "u-7", then)}, nil
			}
			opts := []oidc.BrokerOption{oidc.WithBrokerLogger(testTextLogger(e.logs)), oidc.WithBrokerSignInHook("corp", hook)}
			if tc.ids != nil {
				opts = append(opts, tc.ids(ctrl))
			}
			b, err := oidc.NewBroker(links, e.dir.loader(ctrl), opts...)
			require.NoError(t, err)

			p, err := b.BrokerUpstream(ctx, ext, oidc.NewUpstreamForTest(hookToken, "s-1", nil, nil))
			tc.assert(t, e, p, err)
		})
	}
}

func TestBroker_HookOneLinkPerUser(t *testing.T) {
	t.Parallel()

	type env struct {
		links   *oidc.MemoryLinkStore
		applies *applyRecord
	}
	type testCase struct {
		name    string
		seed    []oidc.Link
		subject string // the signing-in corp identity's subject
		opts    []oidc.BrokerOption
		assert  func(t *testing.T, e env, p *identity.Principal, err error)
	}

	partnerLink := oidc.Link{Provider: "partner", Issuer: "https://partner.example", Subject: "p-1", UserID: "u-7"}
	otherIssuer := corpLink("s-9", "u-7")
	otherIssuer.Issuer = "https://corp-eu.example"

	refused := func(t *testing.T, e env, p *identity.Principal, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
		assert.Nil(t, p)
		assert.Empty(t, e.applies.all(), "a second link is refused before the apply step")
		assert.Nil(t, findCorp(t, e.links, "s-2"), "no link for s-2")
		l := findCorp(t, e.links, "s-1")
		require.NotNil(t, l, "the user's first link stays")
		assert.Equal(t, identity.UserID("u-7"), l.UserID)
	}
	linked := func(t *testing.T, e env, p *identity.Principal, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Equal(t, identity.UserID("u-7"), p.ID)
		l := findCorp(t, e.links, "s-2")
		require.NotNil(t, l)
		assert.Equal(t, identity.UserID("u-7"), l.UserID)
		assert.Len(t, e.applies.all(), 1)
	}
	// twoLinks is a user already holding two links from corp's issuer, a state
	// a lost race or an operator can leave behind.
	twoLinks := []oidc.Link{corpLink("s-1", "u-7"), corpLink("s-2", "u-7")}
	bothKept := func(t *testing.T, e env) {
		t.Helper()
		for _, s := range []string{"s-1", "s-2"} {
			l := findCorp(t, e.links, s)
			require.NotNil(t, l, "the existing link of %s stays", s)
			assert.Equal(t, identity.UserID("u-7"), l.UserID)
		}
	}
	refusedThroughEither := func(t *testing.T, e env, p *identity.Principal, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
		assert.Nil(t, p)
		assert.Empty(t, e.applies.all(), "a user holding two links is refused before the apply step")
		bothKept(t, e)
	}
	signsInThroughEither := func(t *testing.T, e env, p *identity.Principal, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Equal(t, identity.UserID("u-7"), p.ID)
		assert.Len(t, e.applies.all(), 1)
		bothKept(t, e)
	}

	cases := []testCase{
		{
			name:    "a user holding two links from the issuer is refused through the first, and both links stay",
			seed:    twoLinks,
			subject: "s-1",
			assert:  refusedThroughEither,
		},
		{
			name:    "a user holding two links from the issuer is refused through the second, and both links stay",
			seed:    twoLinks,
			subject: "s-2",
			assert:  refusedThroughEither,
		},
		{
			name:    "with many links allowed for corp, a user holding two links signs in through the first",
			seed:    twoLinks,
			subject: "s-1",
			opts:    []oidc.BrokerOption{oidc.WithBrokerSignInHookAllowManyLinks("corp")},
			assert:  signsInThroughEither,
		},
		{
			name:    "with many links allowed for corp, a user holding two links signs in through the second",
			seed:    twoLinks,
			subject: "s-2",
			opts:    []oidc.BrokerOption{oidc.WithBrokerSignInHookAllowManyLinks("corp")},
			assert:  signsInThroughEither,
		},
		{
			name:    "a second subject of the same issuer decided for a linked user is refused before the apply step",
			seed:    []oidc.Link{corpLink("s-1", "u-7")},
			subject: "s-2",
			assert:  refused,
		},
		{
			name:    "with many links allowed for corp, the second subject is linked",
			seed:    []oidc.Link{corpLink("s-1", "u-7")},
			subject: "s-2",
			opts:    []oidc.BrokerOption{oidc.WithBrokerSignInHookAllowManyLinks("corp")},
			assert:  linked,
		},
		{
			name:    "a link of the user from another provider or issuer does not count",
			seed:    []oidc.Link{partnerLink, otherIssuer},
			subject: "s-2",
			assert:  linked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			links := oidc.NewMemoryLinkStore()
			for i, l := range tc.seed {
				l.ID = id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", i+1))
				require.NoError(t, links.Insert(t.Context(), l))
			}
			e := env{links: links, applies: &applyRecord{}}
			hook := func(_ context.Context, ext oidc.ExternalIdentity, _ oidc.Upstream, _ identity.UserID) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{User: "u-7", Apply: e.applies.step(links, ext, "u-7", nil)}, nil
			}
			dir := newHookDirectory(activeUser("u-7"))
			b, err := oidc.NewBroker(links, dir.loader(gomock.NewController(t)),
				append([]oidc.BrokerOption{oidc.WithBrokerSignInHook("corp", hook)}, tc.opts...)...)
			require.NoError(t, err)

			p, err := b.BrokerUpstream(t.Context(), corpIdentity(tc.subject),
				oidc.NewUpstreamForTest(hookToken, tc.subject, nil, nil))
			tc.assert(t, e, p, err)
		})
	}
}

// barrierLinks is a memory link store that holds the first two calls of one
// method until both have arrived, so two racing logins both pass that point
// before either goes on.
type barrierLinks struct {
	*oidc.MemoryLinkStore
	method  string // "find" or "list"
	calls   atomic.Int32
	both    chan struct{} // closed when the second call arrives
	timeout <-chan time.Time
}

func newBarrierLinks(method string) *barrierLinks {
	return &barrierLinks{
		MemoryLinkStore: oidc.NewMemoryLinkStore(), method: method,
		both: make(chan struct{}), timeout: time.After(10 * time.Second),
	}
}

func (s *barrierLinks) hold(method string) {
	if method != s.method {
		return
	}
	switch s.calls.Add(1) {
	case 1:
		select {
		case <-s.both:
		case <-s.timeout: // the other login never arrived; the row's assertions say why
		}
	case 2:
		close(s.both)
	}
}

func (s *barrierLinks) FindByExternal(ctx context.Context, provider, issuer, subject string) (*oidc.Link, error) {
	l, err := s.MemoryLinkStore.FindByExternal(ctx, provider, issuer, subject)
	s.hold("find")
	return l, err
}

func (s *barrierLinks) ListByUser(ctx context.Context, user identity.UserID) ([]oidc.Link, error) {
	l, err := s.MemoryLinkStore.ListByUser(ctx, user)
	s.hold("list")
	return l, err
}

func TestBroker_HookRaces(t *testing.T) {
	t.Parallel()

	type login struct {
		subject string
		decide  identity.UserID
	}
	type outcome struct {
		login
		p   *identity.Principal
		err error
	}
	type testCase struct {
		name    string
		barrier string // the method both logins are held after
		logins  [2]login
		assert  func(t *testing.T, links *barrierLinks, applies *applyRecord, out [2]outcome)
	}

	// corpLinks returns every corp link the store holds for the subjects.
	corpLinks := func(t *testing.T, links oidc.LinkStore, subjects ...string) []oidc.Link {
		t.Helper()
		var all []oidc.Link
		for _, s := range subjects {
			if l := findCorp(t, links, s); l != nil {
				all = append(all, *l)
			}
		}
		return all
	}

	cases := []testCase{
		{
			name:    "two first sign-ins of one identity deciding u-7 leave one link, both resolve, both apply after it",
			barrier: "find",
			logins:  [2]login{{"s-1", "u-7"}, {"s-1", "u-7"}},
			assert: func(t *testing.T, links *barrierLinks, applies *applyRecord, out [2]outcome) {
				for _, o := range out {
					require.NoError(t, o.err)
					assert.Equal(t, identity.UserID("u-7"), o.p.ID)
				}
				l := findCorp(t, links, "s-1")
				require.NotNil(t, l)
				calls := applies.all()
				require.Len(t, calls, 2)
				for _, c := range calls {
					assert.Equal(t, identity.UserID("u-7"), c.target)
					assert.Equal(t, l, c.link, "every apply step ran after the one final link")
				}
			},
		},
		{
			name:    "two first sign-ins of one identity deciding u-7 and u-9: one wins, the other is refused and never applies",
			barrier: "find",
			logins:  [2]login{{"s-1", "u-7"}, {"s-1", "u-9"}},
			assert: func(t *testing.T, links *barrierLinks, applies *applyRecord, out [2]outcome) {
				var won []outcome
				for _, o := range out {
					if o.err == nil {
						won = append(won, o)
						continue
					}
					require.ErrorIs(t, o.err, oidc.ErrNoLinkedAccount)
				}
				require.Len(t, won, 1)
				assert.Equal(t, won[0].decide, won[0].p.ID)
				l := findCorp(t, links, "s-1")
				require.NotNil(t, l)
				assert.Equal(t, won[0].decide, l.UserID)
				calls := applies.all()
				require.Len(t, calls, 1, "the loser's apply step never ran")
				assert.Equal(t, won[0].decide, calls[0].target)
			},
		},
		{
			name:    "two new subjects deciding u-7 leave at most one link, and every refused login never applies",
			barrier: "list",
			logins:  [2]login{{"s-1", "u-7"}, {"s-2", "u-7"}},
			assert: func(t *testing.T, links *barrierLinks, applies *applyRecord, out [2]outcome) {
				remaining := corpLinks(t, links, "s-1", "s-2")
				require.LessOrEqual(t, len(remaining), 1, "at most one link to u-7 from the issuer remains: %v", remaining)
				var wonSubjects []string
				for _, o := range out {
					if o.err != nil {
						require.ErrorIs(t, o.err, oidc.ErrNoLinkedAccount)
						assert.Nil(t, findCorp(t, links, o.subject), "a refused login's link was removed")
						continue
					}
					assert.Equal(t, identity.UserID("u-7"), o.p.ID)
					wonSubjects = append(wonSubjects, o.subject)
				}
				require.Len(t, remaining, len(wonSubjects), "every winner keeps its link")
				calls := applies.all()
				require.Len(t, calls, len(wonSubjects), "only winners applied")
				for _, c := range calls {
					require.NotNil(t, c.link)
					assert.Contains(t, wonSubjects, c.link.Subject)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			links := newBarrierLinks(tc.barrier)
			applies := &applyRecord{}
			hook := func(_ context.Context, ext oidc.ExternalIdentity, up oidc.Upstream, _ identity.UserID) (oidc.SignInDecision, error) {
				// Each login's access token carries its decision, which tells two
				// logins of one identity apart.
				decide := identity.UserID(up.AccessToken())
				return oidc.SignInDecision{User: decide, Apply: applies.step(links, ext, decide, nil)}, nil
			}
			dir := newHookDirectory(activeUser("u-7"), activeUser("u-9"))
			b, err := oidc.NewBroker(links, dir.loader(gomock.NewController(t)), oidc.WithBrokerSignInHook("corp", hook))
			require.NoError(t, err)

			var (
				out [2]outcome
				wg  sync.WaitGroup
			)
			for i, l := range tc.logins {
				wg.Go(func() {
					p, err := b.BrokerUpstream(t.Context(), corpIdentity(l.subject),
						oidc.NewUpstreamForTest(string(l.decide), l.subject, nil, nil))
					out[i] = outcome{login: l, p: p, err: err}
				})
			}
			wg.Wait()
			require.EqualValues(t, 2, min(links.calls.Load(), 2), "both logins reached the barrier")
			tc.assert(t, links, applies, out)
		})
	}
}

// stagedLogin is the context key naming the login a stagedLinks call belongs
// to.
type stagedLogin struct{}

// stagedLinks is a memory link store that runs a per-login stage before an
// insert, after it, or before a removal, so a row can interleave several
// logins step by step. Like a database driver, it refuses ListByUser and
// DeleteLink once their context is done.
type stagedLinks struct {
	*oidc.MemoryLinkStore
	mu           sync.Mutex
	beforeInsert map[string]func()
	afterInsert  map[string]func()
	beforeDelete map[string]func(ctx context.Context)
}

func newStagedLinks() *stagedLinks {
	return &stagedLinks{
		MemoryLinkStore: oidc.NewMemoryLinkStore(),
		beforeInsert:    map[string]func(){}, afterInsert: map[string]func(){},
		beforeDelete: map[string]func(ctx context.Context){},
	}
}

func (s *stagedLinks) stage(m map[string]func(), ctx context.Context) {
	name, _ := ctx.Value(stagedLogin{}).(string)
	s.mu.Lock()
	f := m[name]
	s.mu.Unlock()
	if f != nil {
		f()
	}
}

func (s *stagedLinks) Insert(ctx context.Context, l oidc.Link) error {
	s.stage(s.beforeInsert, ctx)
	err := s.MemoryLinkStore.Insert(ctx, l)
	s.stage(s.afterInsert, ctx)
	return err
}

func (s *stagedLinks) ListByUser(ctx context.Context, user identity.UserID) ([]oidc.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.MemoryLinkStore.ListByUser(ctx, user)
}

func (s *stagedLinks) DeleteLink(ctx context.Context, l oidc.Link) (bool, error) {
	name, _ := ctx.Value(stagedLogin{}).(string)
	s.mu.Lock()
	f := s.beforeDelete[name]
	s.mu.Unlock()
	if f != nil {
		f(ctx)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return s.MemoryLinkStore.DeleteLink(ctx, l)
}

// awaitStage waits for c to close, and reports a stage that never came
// rather than hanging the test.
func awaitStage(t *testing.T, c <-chan struct{}, what string) {
	select {
	case <-c:
	case <-time.After(10 * time.Second):
		t.Errorf("timed out waiting for %s", what)
	}
}

// TestBroker_HookUndoInterleavings drives logins step by step around the
// removal of a link inserted against the one-link rule (D11).
func TestBroker_HookUndoInterleavings(t *testing.T) {
	t.Parallel()

	type outcome struct {
		p   *identity.Principal
		err error
	}
	type env struct {
		links   *stagedLinks
		applies *applyRecord
		// login signs in through subject as the named login, under ctx.
		login func(ctx context.Context, name, subject string) outcome
	}
	type testCase struct {
		name string
		// run interleaves the row's logins and returns each one's outcome by name.
		run    func(t *testing.T, e env) map[string]outcome
		assert func(t *testing.T, e env, out map[string]outcome)
	}

	cases := []testCase{
		{
			// A (s-2) passes its pre-check; B (s-1) links u-7 and signs in; A
			// inserts s-2, its re-check sees s-1, and before A removes s-2, C (s-2
			// again) finds A's link.
			name: "a sign-in finding a link its inserter is about to undo is refused, never signed in through it",
			run: func(t *testing.T, e env) map[string]outcome {
				aAtInsert, bDone, aAtUndo, cDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
				e.links.beforeInsert["A"] = func() { close(aAtInsert); awaitStage(t, bDone, "B to finish") }
				e.links.beforeDelete["A"] = func(context.Context) { close(aAtUndo); awaitStage(t, cDone, "C to finish") }

				out := map[string]outcome{}
				var wg sync.WaitGroup
				var a outcome
				wg.Go(func() { a = e.login(t.Context(), "A", "s-2") })
				awaitStage(t, aAtInsert, "A to reach its insert")
				out["B"] = e.login(t.Context(), "B", "s-1")
				close(bDone)
				awaitStage(t, aAtUndo, "A to reach its undo")
				out["C"] = e.login(t.Context(), "C", "s-2")
				close(cDone)
				wg.Wait()
				out["A"] = a
				return out
			},
			assert: func(t *testing.T, e env, out map[string]outcome) {
				require.NoError(t, out["B"].err)
				assert.Equal(t, identity.UserID("u-7"), out["B"].p.ID)
				for _, name := range []string{"A", "C"} {
					require.ErrorIs(t, out[name].err, oidc.ErrNoLinkedAccount, "login %s", name)
					assert.Nil(t, out[name].p, "login %s", name)
				}
				assert.Nil(t, findCorp(t, e.links, "s-2"), "A removed the link it inserted")
				l := findCorp(t, e.links, "s-1")
				require.NotNil(t, l, "B keeps its link")
				calls := e.applies.all()
				require.Len(t, calls, 1, "only B applied")
				require.NotNil(t, calls[0].link)
				assert.Equal(t, "s-1", calls[0].link.Subject)
			},
		},
		{
			// A (s-1) passes its pre-check; B (s-2) links u-7 and signs in; A
			// inserts s-1 and its client goes away at once.
			name: "a request cancelled after its insert still removes its duplicate, under a bounded deadline",
			run: func(t *testing.T, e env) map[string]outcome {
				ctxA, cancelA := context.WithCancel(t.Context())
				defer cancelA()
				aAtInsert, bDone := make(chan struct{}), make(chan struct{})
				e.links.beforeInsert["A"] = func() { close(aAtInsert); awaitStage(t, bDone, "B to finish") }
				e.links.afterInsert["A"] = cancelA
				var undoDeadline time.Duration
				var undoHasDeadline bool
				e.links.beforeDelete["A"] = func(ctx context.Context) {
					d, ok := ctx.Deadline()
					undoHasDeadline, undoDeadline = ok, time.Until(d)
				}

				out := map[string]outcome{}
				var wg sync.WaitGroup
				var a outcome
				wg.Go(func() { a = e.login(ctxA, "A", "s-1") })
				awaitStage(t, aAtInsert, "A to reach its insert")
				out["B"] = e.login(t.Context(), "B", "s-2")
				close(bDone)
				wg.Wait()
				out["A"] = a
				assert.True(t, undoHasDeadline, "the undo is bounded")
				assert.LessOrEqual(t, undoDeadline, 5*time.Second, "the undo's bound is short")
				return out
			},
			assert: func(t *testing.T, e env, out map[string]outcome) {
				require.NoError(t, out["B"].err)
				assert.Equal(t, identity.UserID("u-7"), out["B"].p.ID)
				assertBrokerFailure(t, out["A"].p, out["A"].err)
				require.ErrorIs(t, out["A"].err, context.Canceled)
				all, err := e.links.MemoryLinkStore.ListByUser(t.Context(), "u-7")
				require.NoError(t, err)
				require.Len(t, all, 1, "u-7 keeps one link from corp's issuer: %+v", all)
				assert.Equal(t, "s-2", all[0].Subject, "B keeps its link")
			},
		},
		{
			// A (s-1) and C (s-1 again) pass their pre-checks; B (s-2) links u-7.
			// A inserts s-1, its re-check sees s-2 and A starts its undo. C inserts
			// s-1 and finds it linked, and A's undo removes the link before C
			// re-reads it.
			name: "a sign-in whose link was undone between its insert and its re-read is refused as a lost race",
			run: func(t *testing.T, e env) map[string]outcome {
				aAtInsert, cAtInsert, goA, goC := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
				aAtUndo, goDelete, aDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
				e.links.beforeInsert["A"] = func() { close(aAtInsert); awaitStage(t, goA, "A to be released") }
				e.links.beforeInsert["C"] = func() { close(cAtInsert); awaitStage(t, goC, "C to be released") }
				e.links.beforeDelete["A"] = func(context.Context) { close(aAtUndo); awaitStage(t, goDelete, "A's undo to be released") }
				e.links.afterInsert["C"] = func() { close(goDelete); awaitStage(t, aDone, "A to finish") }

				out := map[string]outcome{}
				var wg sync.WaitGroup
				var a, c outcome
				wg.Go(func() { a = e.login(t.Context(), "A", "s-1"); close(aDone) })
				wg.Go(func() { c = e.login(t.Context(), "C", "s-1") })
				awaitStage(t, aAtInsert, "A to reach its insert")
				awaitStage(t, cAtInsert, "C to reach its insert")
				out["B"] = e.login(t.Context(), "B", "s-2")
				close(goA)
				awaitStage(t, aAtUndo, "A to reach its undo")
				close(goC)
				wg.Wait()
				out["A"], out["C"] = a, c
				return out
			},
			assert: func(t *testing.T, e env, out map[string]outcome) {
				require.NoError(t, out["B"].err)
				for _, name := range []string{"A", "C"} {
					require.ErrorIs(t, out[name].err, oidc.ErrNoLinkedAccount, "login %s", name)
					assert.Nil(t, out[name].p, "login %s", name)
				}
				assert.Nil(t, findCorp(t, e.links, "s-1"), "A removed the link")
				assert.Len(t, e.applies.all(), 1, "only B applied")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			links := newStagedLinks()
			applies := &applyRecord{}
			hook := func(_ context.Context, ext oidc.ExternalIdentity, _ oidc.Upstream, _ identity.UserID) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{User: "u-7", Apply: applies.step(links, ext, "u-7", nil)}, nil
			}
			dir := newHookDirectory(activeUser("u-7"))
			b, err := oidc.NewBroker(links, dir.loader(gomock.NewController(t)), oidc.WithBrokerSignInHook("corp", hook))
			require.NoError(t, err)

			e := env{links: links, applies: applies}
			e.login = func(ctx context.Context, name, subject string) outcome {
				ctx = context.WithValue(ctx, stagedLogin{}, name)
				p, err := b.BrokerUpstream(ctx, corpIdentity(subject), oidc.NewUpstreamForTest(hookToken, subject, nil, nil))
				return outcome{p: p, err: err}
			}
			out := tc.run(t, e)
			tc.assert(t, e, out)
		})
	}
}
