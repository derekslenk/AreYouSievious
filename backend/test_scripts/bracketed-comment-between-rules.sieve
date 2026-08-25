# A bracketed comment (RFC 5228 §2.3) sitting between two LIVE rules, plus one
# after the last rule. The rule below the comment used to be fused into a
# single opaque RawBlock together with the commented-out rule and the closing
# `*/`, so a rule the server executes was un-editable in the builder
# (areyousievious-hr6).
require ["fileinto"];

# --- subject a ---
if header :contains "subject" "a" { fileinto "A"; }

/*
if header :contains "subject" "b" { fileinto "B"; }
*/

# --- subject c ---
if header :contains "subject" "c" { fileinto "C"; }

/* nothing below here is live either */
