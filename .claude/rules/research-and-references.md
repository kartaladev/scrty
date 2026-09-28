# Rule: Research before asking for a decision, and record the sources with it

A decision question — options put to the user with a recommendation — is only as good as the
research behind it. Research first, present what was found, and record the sources beside the
decision, so a later reader (human or agent) can see why it was made and check it again.

## 1. Research before putting a decision to the user

Before offering a decision question, research the topic, in this order:

1. **The project.** Settled specs under `openspec/specs/`, the artifacts of active changes, and the
   code, navigated with gopls (`gopls-navigation.md`). Do not ask the user for a fact the project
   already states.
2. **The legacy reference**, when the topic is a behaviour, edge case or trade-off the predecessor
   handled. Its behaviour is the default under `legacy-reference.md`'s precedence, so it must be
   known before an option departs from it. Consult it as that rule says, and never cite it (see
   section 2).
3. **Standards and primary sources.** NIST, W3C, IETF RFCs, OWASP, FIDO, and the documentation of
   the libraries and systems involved.
4. **Established practice.** How reputable libraries and major services solve the same problem.
5. **Live facts, checked live.** Library maintenance, stars, releases and known vulnerabilities come
   from the GitHub and OSV APIs, and API shapes from `go doc` or pkg.go.dev, not from memory.

Then present:

- each option with its pros and cons, and sample code where it helps the user compare;
- a recommendation, with the reasons for it;
- the sources, listed at the end of the reply.

A claim that could not be verified is labelled as unverified, never stated as fact. A question
only the user can answer (their intent, priorities or constraints) is asked directly, without
research invented to justify an answer.

## 2. Record the sources with the decision

When a researched decision is written into a change, record its sources in that change:

- **Where:**
  - in the proposal's `## References` section while the change has no `design.md`;
  - in `design.md`'s `## References` section once it exists. Carry the proposal's references
    forward, next to the decisions they support.
- **Grouping:** by the decision each source supports.
- **Each entry:** a markdown link, and one line on what it supports.
- **Two labelled groups:**
  - **Researched:** consulted for the decision, with the date they were accessed;
  - **Primary documentation:** standard references the design relies on and cites as such, without
    re-checking them on that date.
- **Live figures** (stars, release counts, vulnerability counts) carry the date they were read and
  a note that they drift.
- **A paywalled or registration-only standard** is cited through public secondary sources, and the
  entry says so.
- **Specs carry no references.** They state requirements only.
- **The legacy reference is never a reference.** `legacy-reference.md` forbids citing the
  predecessor in any OpenSpec artifact, and that holds here without exception:
  - it never appears in a References section, by name, path or link;
  - where a design must mention its behaviour — for a departure, or a default taken from it — it
    calls it "the established design", as existing designs do, and records the departure as
    `legacy-reference.md` requires.

  A decision that rests only on the legacy reference and the project's own specs says so in its
  References section, without naming the legacy reference: "reasoned from scrty's own settled
  specs and the established design".

## 3. Keep references current

When a decision changes or is reversed, update its references in the same pass, and remove the ones
that no longer support anything.

## 4. Who does it

The main session writes References sections, because OpenSpec artifacts are its to write
(`subagent-delegation.md`). A research subagent may gather sources and report them. It never edits
an artifact.

## Never

- Invent a source, or cite as read a source that was not read.
- Present a remembered figure, quote or API shape as verified.
- Cite the legacy reference in any artifact (`legacy-reference.md`).
- Offer a decision question on a topic with established standards or practice without researching
  it first.
