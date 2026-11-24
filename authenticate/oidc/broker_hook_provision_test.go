package oidc_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// create stores u, as an apply step that provisions its user does.
func (d *hookDirectory) create(u identity.Details) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[u.ID] = u
}

// loadAs makes ref load as as's details from now on.
func (d *hookDirectory) loadAs(ref, as identity.UserID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadsAs[ref] = as
}

// provisionLinks is a memory link store that counts inserts, and may run a
// write of its own before an insert, or fail it.
type provisionLinks struct {
	*oidc.MemoryLinkStore
	inserts      atomic.Int32
	beforeInsert func(ctx context.Context, s *oidc.MemoryLinkStore) // nil means none
	insertErr    error                                              // nil means insert
	listErr      error                                              // nil means list
}

func (s *provisionLinks) ListByUser(ctx context.Context, u identity.UserID) ([]oidc.Link, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.MemoryLinkStore.ListByUser(ctx, u)
}

func (s *provisionLinks) Insert(ctx context.Context, l oidc.Link) error {
	s.inserts.Add(1)
	if s.beforeInsert != nil {
		s.beforeInsert(ctx, s.MemoryLinkStore)
	}
	if s.insertErr != nil {
		return s.insertErr
	}
	return s.MemoryLinkStore.Insert(ctx, l)
}

func TestBroker_HookProvisions(t *testing.T) {
	t.Parallel()

	ext := corpIdentity("s-1")
	pending := corpLink("s-1", "u-new")
	pending.ID = id.MustParse("01926a4e-0000-7000-8000-000000000061")
	pending.Username = "" // as a provisioning sign-in stores it

	type env struct {
		links   *provisionLinks
		dir     *hookDirectory
		applies *applyRecord
		linked  []identity.UserID // the linked user the hook was handed, per call
		logs    string
	}
	type testCase struct {
		name    string
		ctx     func(ctx context.Context) context.Context
		seed    []oidc.Link // links stored before the login
		opts    []oidc.BrokerOption
		prepare func(d *hookDirectory, s *provisionLinks)
		decide  identity.UserID // empty means u-new
		noApply bool
		// then is the apply step's own work, after it recorded itself; nil
		// creates the decided user, active.
		then   func(d *hookDirectory) func(ctx context.Context) error
		assert func(t *testing.T, e env, p *identity.Principal, err error)
	}

	// refusedBeforeWrite asserts a refusal that wrote nothing.
	refusedBeforeWrite := func(t *testing.T, e env, p *identity.Principal, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
		assert.Nil(t, p)
		assert.Empty(t, e.applies.all(), "a refused decision never runs its apply step")
		assert.Nil(t, findCorp(t, e.links, "s-1"), "a refused decision writes no link")
		assert.Zero(t, e.links.inserts.Load())
	}
	// linkStays asserts the identity's link to u-new, with an empty
	// username, survived a failed login.
	linkStays := func(t *testing.T, e env) {
		t.Helper()
		l := findCorp(t, e.links, "s-1")
		require.NotNil(t, l, "the link to the user being provisioned stays for a later sign-in to resume")
		assert.Equal(t, identity.UserID("u-new"), l.UserID)
		assert.Empty(t, l.Username)
	}
	leak := errors.New("db down s-1 alice@corp.example u-new " + hookToken)

	partnerLink := oidc.Link{
		Provider: "partner", Issuer: "https://partner.example", Subject: "p-1",
		UserID: "u-new", Username: "name-u-new", Email: "alice@partner.example",
	}
	partnerLinkFor := func(u identity.UserID) oidc.Link {
		l := partnerLink
		l.UserID = u
		return l
	}
	manyLinks := []oidc.BrokerOption{oidc.WithBrokerSignInHookAllowManyLinks("corp")}
	// freshRefused asserts the reference was refused as not fresh, with the
	// other identity's link untouched.
	freshRefused := func(other oidc.Link) func(t *testing.T, e env, p *identity.Principal, err error) {
		return func(t *testing.T, e env, p *identity.Principal, err error) {
			refusedBeforeWrite(t, e, p, err)
			got, ferr := e.links.FindByExternal(t.Context(), other.Provider, other.Issuer, other.Subject)
			require.NoError(t, ferr, "the other identity's link is untouched")
			assert.Equal(t, other.UserID, got.UserID)
			assert.Contains(t, e.logs, "level=DEBUG", e.logs)
			assert.Contains(t, e.logs, "provider=corp")
			assertScrubbed(t, e.logs, "u-new")
		}
	}

	cases := []testCase{
		{
			name:   "provisioning absent u-new, which another provider's link names, is refused before any write: the reference is not fresh",
			seed:   []oidc.Link{partnerLink},
			assert: freshRefused(partnerLink),
		},
		{
			name:   "provisioning absent u-new, which another subject of the same provider's link names under allow-many, is refused",
			seed:   []oidc.Link{corpLink("s-2", "u-new")},
			opts:   manyLinks,
			assert: freshRefused(corpLink("s-2", "u-new")),
		},
		{
			name: "a fresh u-new that no link names still provisions under allow-many, beside links of other users",
			seed: []oidc.Link{corpLink("s-2", "u-7"), partnerLinkFor("u-8")},
			opts: manyLinks,
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("u-new"), p.ID)
				assert.EqualValues(t, 1, e.links.inserts.Load())
			},
		},
		{
			name:    "a link listing fault while checking the reference is a redacted broker failure, and nothing is written",
			opts:    manyLinks,
			prepare: func(_ *hookDirectory, s *provisionLinks) { s.listErr = leak },
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				require.ErrorIs(t, err, leak)
				assertScrubbed(t, err.Error(), "u-new")
				assert.Empty(t, e.applies.all())
				assert.Nil(t, findCorp(t, e.links, "s-1"))
				assert.Zero(t, e.links.inserts.Load())
			},
		},
		{
			name: "a first sign-in provisioning u-new links it with an empty username before Apply creates it, and resolves to u-new",
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("u-new"), p.ID)
				assert.Equal(t, []identity.UserID{""}, e.linked)
				l := findCorp(t, e.links, "s-1")
				require.NotNil(t, l)
				assert.Equal(t, identity.UserID("u-new"), l.UserID)
				assert.Empty(t, l.Username, "no user existed to name when the link was stored")
				assert.Equal(t, "alice@corp.example", l.Email)
				assert.NotEqual(t, id.Nil, l.ID)
				calls := e.applies.all()
				require.Len(t, calls, 1)
				require.NotNil(t, calls[0].link, "the link exists when Apply runs")
				assert.Equal(t, *l, *calls[0].link)
				assert.EqualValues(t, 1, e.links.inserts.Load())
			},
		},
		{
			name:   "provisioning u-7, which exists and is not linked to the identity, is refused with one warning: never adopted (F32)",
			decide: "u-7",
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				refusedBeforeWrite(t, e, p, err)
				assert.Equal(t, 1, strings.Count(e.logs, "level=WARN"), e.logs)
				assert.Contains(t, e.logs, "provider=corp")
				assert.Contains(t, e.logs, "email_domain=corp.example")
				assertScrubbed(t, e.logs, "u-7", "name-u-7")
			},
		},
		{
			name:    "provisioning with no Apply is a broker failure, and nothing is written (F33)",
			noApply: true,
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				assertScrubbed(t, err.Error(), "u-new")
				assert.Nil(t, findCorp(t, e.links, "s-1"))
				assert.Zero(t, e.links.inserts.Load())
			},
		},
		{
			name: "an Apply that fails is a broker failure with fixed text, and the link stays (F34)",
			then: func(*hookDirectory) func(context.Context) error {
				return func(context.Context) error { return errors.New("create failed u-new alice@corp.example") }
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				assert.NotContains(t, err.Error(), "create failed")
				assertScrubbed(t, err.Error(), "u-new")
				assert.Len(t, e.applies.all(), 1)
				linkStays(t, e)
			},
		},
		{
			name: "an Apply that returns without creating u-new is a broker failure, not a refusal, and the link stays (F34)",
			then: func(*hookDirectory) func(context.Context) error {
				return func(context.Context) error { return nil }
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				assertScrubbed(t, err.Error(), "u-new")
				assert.Len(t, e.applies.all(), 1)
				linkStays(t, e)
			},
		},
		{
			name: "a later sign-in provisioning the absent u-new its link names inserts nothing, applies, and resolves (F34 resume)",
			seed: []oidc.Link{pending},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("u-new"), p.ID)
				assert.Equal(t, []identity.UserID{"u-new"}, e.linked)
				assert.Zero(t, e.links.inserts.Load())
				assert.Equal(t, &pending, findCorp(t, e.links, "s-1"), "the stored link is unchanged")
				require.Len(t, e.applies.all(), 1)
			},
		},
		{
			name:    "a sign-in provisioning u-new again once it exists, active, through its link applies again and resolves",
			seed:    []oidc.Link{pending},
			prepare: func(d *hookDirectory, _ *provisionLinks) { d.create(activeUser("u-new")) },
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-new"), p.ID)
				assert.Zero(t, e.links.inserts.Load())
				require.Len(t, e.applies.all(), 1)
			},
		},
		{
			// F56: u-new was provisioned through corp, then partner's hook
			// adopted it; corp's identity resuming its own provisioning is not
			// a first provisioning, so the freshness check does not refuse it.
			name: "a sign-in provisioning u-new again through its own link, after another provider's hook adopted u-new, " +
				"applies once and resolves (F56)",
			seed:    []oidc.Link{pending, partnerLink},
			prepare: func(d *hookDirectory, _ *provisionLinks) { d.create(activeUser("u-new")) },
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("u-new"), p.ID)
				assert.Equal(t, []identity.UserID{"u-new"}, e.linked)
				assert.Zero(t, e.links.inserts.Load())
				require.Len(t, e.applies.all(), 1)
				got, ferr := e.links.FindByExternal(t.Context(), "partner", "https://partner.example", "p-1")
				require.NoError(t, ferr, "the other provider's link is untouched")
				assert.Equal(t, identity.UserID("u-new"), got.UserID)
			},
		},
		{
			// F48: partner's leftover race link (empty username, a failed
			// undo) names u-new, which does not exist yet; resuming through
			// corp's own link must not let two identities share one pending
			// user, so freshness runs while the user does not load.
			name: "a sign-in resuming the absent u-new through its own link, while another identity's leftover link names it, " +
				"is refused before Apply and both links stay (F48)",
			seed: func() []oidc.Link {
				leftover := partnerLink
				leftover.Username = ""
				return []oidc.Link{pending, leftover}
			}(),
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Empty(t, e.applies.all(), "a refused resume never runs its apply step")
				assert.Zero(t, e.links.inserts.Load())
				assert.Equal(t, &pending, findCorp(t, e.links, "s-1"), "the identity's own link is unchanged")
				got, ferr := e.links.FindByExternal(t.Context(), "partner", "https://partner.example", "p-1")
				require.NoError(t, ferr, "the other identity's link is untouched")
				assert.Equal(t, identity.UserID("u-new"), got.UserID)
				assert.Empty(t, got.Username)
			},
		},
		{
			name: "a sign-in provisioning u-new again while it exists disabled is refused before Apply, and the link stays",
			seed: []oidc.Link{pending},
			prepare: func(d *hookDirectory, _ *provisionLinks) {
				d.create(activeUser("u-new"))
				d.disable("u-new")
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Empty(t, e.applies.all())
				linkStays(t, e)
			},
		},
		{
			name:    "a loader fault on the check before the link is a redacted broker failure, and nothing is written",
			prepare: func(d *hookDirectory, _ *provisionLinks) { d.fault = leak },
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				require.ErrorIs(t, err, leak, "the fault stays reachable")
				assertScrubbed(t, err.Error(), "u-new")
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
			prepare: func(d *hookDirectory, _ *provisionLinks) { d.fault = context.Canceled },
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, e.applies.all())
				assert.Nil(t, findCorp(t, e.links, "s-1"))
			},
		},
		{
			name: "an Apply that creates u-new disabled is refused, and the link stays",
			then: func(d *hookDirectory) func(context.Context) error {
				return func(context.Context) error {
					d.create(activeUser("u-new"))
					d.disable("u-new")
					return nil
				}
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Len(t, e.applies.all(), 1)
				linkStays(t, e)
			},
		},
		{
			name: "an Apply after which u-new loads as another user is refused, and the link stays",
			then: func(d *hookDirectory) func(context.Context) error {
				return func(context.Context) error { d.loadAs("u-new", "u-7"); return nil }
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				linkStays(t, e)
			},
		},
		{
			name: "an identity linked to u-7 provisioning u-new is refused with one warning, the link unchanged",
			seed: []oidc.Link{corpLink("s-1", "u-7")},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Empty(t, e.applies.all())
				assert.Zero(t, e.links.inserts.Load())
				l := findCorp(t, e.links, "s-1")
				require.NotNil(t, l)
				assert.Equal(t, identity.UserID("u-7"), l.UserID)
				assert.Equal(t, 1, strings.Count(e.logs, "level=WARN"), e.logs)
				assertScrubbed(t, e.logs, "u-7", "u-new")
			},
		},
		{
			name: "provisioning u-new, which another subject of the provider's link names, is refused by the one-link rule",
			seed: []oidc.Link{corpLink("s-2", "u-new")},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				refusedBeforeWrite(t, e, p, err)
				require.NotNil(t, findCorp(t, e.links, "s-2"), "the other subject's link is untouched")
			},
		},
		{
			name: "an insert that finds the identity linked to u-7 meanwhile is refused before Apply, the link naming u-7",
			prepare: func(_ *hookDirectory, s *provisionLinks) {
				s.beforeInsert = func(ctx context.Context, m *oidc.MemoryLinkStore) {
					_ = m.Insert(ctx, corpLink("s-1", "u-7"))
				}
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Empty(t, e.applies.all(), "u-new is never created")
				l := findCorp(t, e.links, "s-1")
				require.NotNil(t, l)
				assert.Equal(t, identity.UserID("u-7"), l.UserID)
			},
		},
		{
			name: "another provider's link to u-new stored between the check and the insert removes this link " +
				"on the re-check, refused before Apply (F52)",
			prepare: func(_ *hookDirectory, s *provisionLinks) {
				s.beforeInsert = func(ctx context.Context, m *oidc.MemoryLinkStore) {
					_ = m.Insert(ctx, partnerLink)
				}
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Empty(t, e.applies.all(), "u-new is never created")
				assert.Nil(t, findCorp(t, e.links, "s-1"), "this sign-in's link was removed")
				got, ferr := e.links.FindByExternal(t.Context(), "partner", "https://partner.example", "p-1")
				require.NoError(t, ferr, "the other identity's link is untouched")
				assert.Equal(t, identity.UserID("u-new"), got.UserID)
				assertScrubbed(t, e.logs, "u-new")
			},
		},
		{
			name: "under allow-many, another subject's link to u-new stored between the check and the insert " +
				"removes this link on the re-check, refused before Apply (F52)",
			opts: manyLinks,
			prepare: func(_ *hookDirectory, s *provisionLinks) {
				s.beforeInsert = func(ctx context.Context, m *oidc.MemoryLinkStore) {
					_ = m.Insert(ctx, corpLink("s-2", "u-new"))
				}
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				assert.Empty(t, e.applies.all(), "u-new is never created")
				assert.Nil(t, findCorp(t, e.links, "s-1"), "this sign-in's link was removed")
				require.NotNil(t, findCorp(t, e.links, "s-2"), "the other subject's link is untouched")
			},
		},
		{
			name: "a link listing fault on the re-check after the insert removes this link and is a redacted " +
				"broker failure, and Apply does not run",
			opts: manyLinks,
			prepare: func(_ *hookDirectory, s *provisionLinks) {
				// Only the listing after the insert fails.
				s.beforeInsert = func(context.Context, *oidc.MemoryLinkStore) { s.listErr = leak }
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				require.ErrorIs(t, err, leak)
				assertScrubbed(t, err.Error(), "u-new")
				assert.Empty(t, e.applies.all())
				assert.EqualValues(t, 1, e.links.inserts.Load())
				assert.Nil(t, findCorp(t, e.links, "s-1"), "this sign-in's link was removed")
			},
		},
		{
			name:    "a link insert fault is a redacted broker failure, and Apply does not run",
			prepare: func(_ *hookDirectory, s *provisionLinks) { s.insertErr = leak },
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				assertBrokerFailure(t, p, err)
				require.ErrorIs(t, err, leak)
				assertScrubbed(t, err.Error(), "u-new")
				assert.Empty(t, e.applies.all())
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
			decide := tc.decide
			if decide == "" {
				decide = "u-new"
			}

			links := &provisionLinks{MemoryLinkStore: oidc.NewMemoryLinkStore()}
			for _, l := range tc.seed {
				require.NoError(t, links.MemoryLinkStore.Insert(t.Context(), l))
			}
			dir := newHookDirectory(activeUser("u-7"), activeUser("u-8"))
			if tc.prepare != nil {
				tc.prepare(dir, links)
			}
			then := func(context.Context) error { dir.create(activeUser(decide)); return nil }
			if tc.then != nil {
				then = tc.then(dir)
			}
			applies := &applyRecord{}
			var (
				mu     sync.Mutex
				linked []identity.UserID
			)
			hook := func(_ context.Context, ext oidc.ExternalIdentity, _ oidc.Upstream, l identity.UserID) (oidc.SignInDecision, error) {
				mu.Lock()
				linked = append(linked, l)
				mu.Unlock()
				d := oidc.SignInDecision{User: decide, Provision: true}
				if !tc.noApply {
					d.Apply = applies.step(links, ext, decide, then)
				}
				return d, nil
			}
			var logs bytes.Buffer
			opts := append([]oidc.BrokerOption{
				oidc.WithBrokerLogger(testTextLogger(&logs)), oidc.WithBrokerSignInHook("corp", hook),
			}, tc.opts...)
			b, err := oidc.NewBroker(links, dir.loader(gomock.NewController(t)), opts...)
			require.NoError(t, err)

			p, err := b.BrokerUpstream(ctx, ext, oidc.NewUpstreamForTest(hookToken, "s-1", nil, nil))
			mu.Lock()
			got := append([]identity.UserID(nil), linked...)
			mu.Unlock()
			tc.assert(t, env{links: links, dir: dir, applies: applies, linked: got, logs: logs.String()}, p, err)
		})
	}
}
