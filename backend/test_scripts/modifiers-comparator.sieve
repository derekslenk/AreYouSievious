require ["fileinto"];

# --- explicit ascii-casemap comparator on a header test ---
if header :comparator "i;ascii-casemap" :contains "subject" "Weekly Report" {
    fileinto "Reports";
}

# --- octet comparator alongside an address part ---
if address :domain :comparator "i;octet" :is "from" "example.com" {
    fileinto "Example";
}
