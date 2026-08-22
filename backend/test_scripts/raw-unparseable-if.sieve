require ["fileinto", "envelope"];

# envelope is not in the visual vocabulary
if envelope :is "to" "sales@example.com" {
    fileinto "Sales";
}

# a size test wrapping a nested if
if size :over 10M {
    if header :contains "subject" "backup" {
        discard;
    }
}
