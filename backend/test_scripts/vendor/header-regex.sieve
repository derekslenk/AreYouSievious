require "regex";
if header :regex "Subject" "^Test" {
    discard;
}
