require ["fileinto"];

# --- a single negated header test ---
if not header :contains "subject" "newsletter" {
    fileinto "Inbox";
}

# --- two negated tests under allof ---
if allof (
    not address :domain :is "from" "example.com",
    not header :is "x-priority" "1"
) {
    fileinto "Other";
}
