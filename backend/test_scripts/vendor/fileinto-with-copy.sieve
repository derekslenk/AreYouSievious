require ["fileinto", "copy"];
if header :contains "subject" "test" {
    fileinto :copy "Spam";
}
