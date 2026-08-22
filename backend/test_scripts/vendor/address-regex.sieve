require "regex";
if address :regex "from" "^test@example\.org$" {
    discard;
}
