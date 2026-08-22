require ["fileinto"];

# --- GitHub notifications ---
## if header :contains "from" "notifications@github.com" {
##     fileinto "GitHub";
## }

# --- still enabled ---
if header :contains "from" "alerts@example.com" {
    fileinto "Alerts";
}
