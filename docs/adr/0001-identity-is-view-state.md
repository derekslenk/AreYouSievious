# Identity is view state; the wire carries no ids

The Sieve script text on the mail server is the only store, and it has nowhere to record an
identity for a Rule, Condition, or Action. The backend was minting `Rule.id` as a fresh
`uuid4` on every parse — two GETs of an unchanged Script returned different ids — so the
wire was carrying an identity that looked durable and wasn't. Meanwhile the SPA needed keys
for Svelte's `{#each}` and minted its own for Conditions and Actions, which the
`extra="forbid"` DTOs then rejected with a 422.

We decided identity is **view state at every level**: the wire carries no ids, and the client
mints whatever keys it needs for rendering and strips them before saving.

## Considered options

**Backend mints ids for all three levels** (Rule, Condition, Action) and they round-trip.
Rejected: it implies a durability guarantee the system cannot honour, because nothing
survives the trip through Sieve text. Positional indices already address entries well enough
for error reporting, which was the main argument in its favour.

**Keep the split** — backend mints Rule ids, client mints the rest. Rejected as the status
quo that produced the bug; it leaves two sources of identity with no owner.

## Consequences

Removing `Rule.id` and its `uuid4` makes `script_to_json` a pure function of its input, so
`Rule` and `SieveScript` become comparable by value. Tests can assert exact payloads instead
of round-trip *stability*, which is what verifying lossless parse/generate fidelity requires.

If a future feature genuinely needs stable identity — cross-session undo, say, or
server-reported per-condition errors — it cannot be bolted onto the wire. It needs a real
store, and that is a much larger decision than adding a field.
