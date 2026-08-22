require "vacation";
if header :contains "subject" "cyrus" {
    vacation "I'm out -- send mail to cyrus-bugs";
} else {
    vacation "I'm out -- call me at +1 304 555 0123";
}
