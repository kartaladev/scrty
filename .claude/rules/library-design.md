# Rule: Opinionated defaults, full consumer control

scrty is a library that other applications embed. It must be **opinionated**: it does the right thing with sensible defaults and no configuration. The consumer must still keep **full control** to customise how it works in their application.

Apply this to every change, whether code, specs or design.

## What that means in practice

1. **Every behaviour has a sensible default that needs no configuration.** A consumer who wires the minimum gets correct, safe behaviour, not a half-working component waiting for options. When "safe" and "convenient" disagree, the default is the safe one, and the convenient one is an option.
2. **Every default is replaceable without forking.** Expose it through a functional option, a port (interface), a hook or plain data. The consumer must never have to copy library code to change a policy. If a default cannot be replaced, the design must say why.
3. **Conventions are documented and optional.** Opinions such as well-known keys, presets, naming layouts or header names are named constants and documented contracts. A consumer may follow them to get the library's integrations for free, or ignore them without losing anything else.
4. **Limits on flexibility are stated, never silently relaxed.** Where full flexibility would break a guarantee the library makes, offer the flexibility up to that line and document the line. For example, if an option would weaken a guarantee the library documents, reject it or document exactly what it gives up. Do not accept the configuration and quietly degrade.
5. **The library does not interpret what the consumer owns.** Consumer-supplied data (payloads, metadata, opaque identifiers, custom attributes) is stored, filtered where promised, and returned unchanged. Its meaning belongs to the consumer.
6. **Wiring mistakes fail at construction.** A contradictory or meaningless configuration is a configuration error from the constructor, before traffic, not a surprise at first use.
7. **Changing a default is a compatibility decision.** Before the first tag it is free, but record it. After a tag it follows the project's release and compatibility policy.

## How to show it

- In each change's `design.md`, every decision that introduces or changes behaviour states **the default** and **how a consumer overrides it**. A decision with no override point explains why it has none.
- In godoc, every option names the default it replaces. Every port says what the library uses when the consumer supplies none.
- In specs, requirements describe the default behaviour, and include a scenario showing the consumer's override where one exists.
- In tests, the default is covered, and so is at least one consumer override.
