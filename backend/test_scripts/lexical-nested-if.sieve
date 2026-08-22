require ["fileinto"];

# a nested block is not single-rule shaped
if header :is "subject" "alpha" {
    if header :is "from" "boss@example.com" {
        fileinto "Urgent";
    }
}
