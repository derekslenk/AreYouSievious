require "copy";
if header :contains "subject" "test" {
    redirect :copy "dev@null.com";
}
