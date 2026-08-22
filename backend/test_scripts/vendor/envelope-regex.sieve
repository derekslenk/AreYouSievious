require ["regex","envelope"];
if envelope :regex "from" "^test@example\.org$" {
    discard;
}
