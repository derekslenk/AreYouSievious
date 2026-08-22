require ["fileinto", "regex"];

# --- regex match on a header ---
if header :regex "subject" "^\\[ticket-[0-9]+\\]" {
    fileinto "Tickets";
}

# --- negated regex on an address ---
if not address :domain :regex "from" "^(mail|smtp)\\.example\\.com$" {
    fileinto "External";
}
