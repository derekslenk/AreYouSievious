# AreYouSievious

Managing Sieve mail filters that live on a user's own mail server. There is no database —
the mail server holds every Script, and the app is a visual editor in front of it.

## Language

### On the mail server

**Script**:
A named Sieve filter program stored on the user's mail server, reached over ManageSieve.
_Avoid_: filter file, filter set, ruleset

**Active Script**:
The one Script the mail server actually applies to incoming mail. An account has at most one.
_Avoid_: enabled script, live script, default script

### Inside a Script

**Entry**:
One item in a Script's ordered sequence — either a Rule or a Raw Block. Position in the
sequence is the order the mail server evaluates them in.
_Avoid_: node, element, item

**Rule**:
An Entry the visual builder can edit: Conditions combined by a match type, plus the Actions
to take when they match.
_Avoid_: filter, policy, handler

**Raw Block**:
An Entry the parser does not recognise, kept verbatim so Sieve the app doesn't understand is
never destroyed.
_Avoid_: unknown block, passthrough, blob

**Condition**:
A test a Rule applies to an incoming message, against a header or an address.
_Avoid_: test, criterion, predicate

**Action**:
What a Rule does to a matching message — file, copy, redirect, keep, discard, stop, flag,
or reject.
_Avoid_: effect, command, operation

**Match type**:
Whether a Rule fires when any of its Conditions hold, or only when all of them do.
_Avoid_: combinator, operator, join
