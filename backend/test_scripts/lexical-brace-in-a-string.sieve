require ["fileinto"];

# --- files into a folder whose name has a brace ---
if header :is "subject" "alpha" {
    fileinto "Weird{Folder";
}

# --- the rule that used to be swallowed ---
if header :is "subject" "beta" {
    fileinto "Beta";
}
