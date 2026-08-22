require ["fileinto"];

# --- address :all ---
if address :all :is "from" "alice@example.com" {
    fileinto "Alice";
}

# --- address :localpart ---
if address :localpart :is "from" "alice" {
    fileinto "Alice";
}

# --- address :domain ---
if address :domain :contains "from" "example.com" {
    fileinto "Example";
}
