require "vacation";
if header :contains "subject" "lunch" {
    vacation :handle "ran-away" "I'm out and can't meet for lunch";
} else {
    vacation :handle "ran-away" "I'm out";
}
