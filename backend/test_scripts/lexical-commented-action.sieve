require ["fileinto"];

# --- one live action and one the user commented out ---
if header :is "subject" "alpha" {
    fileinto "Live";
    # fileinto "Disabled";
}
