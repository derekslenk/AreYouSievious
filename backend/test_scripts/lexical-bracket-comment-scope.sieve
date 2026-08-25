require ["fileinto"];

# --- live ---
if header :contains "subject" "a" {
    fileinto "A";
}

/*
if header :contains "subject" "b" {
    fileinto "B";
}
*/

# --- also live ---
if header :contains "subject" "c" {
    fileinto "C";
}
