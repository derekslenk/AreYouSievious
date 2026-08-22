if header :contains "Sender" "example.com" {
  if header :contains "Sender" "me@" {
    discard;
  } elsif header :contains "Sender" "you@" {
    keep;
  }
}
