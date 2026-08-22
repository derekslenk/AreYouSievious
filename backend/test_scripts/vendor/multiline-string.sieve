require "reject";

if allof (false, address :is ["From", "Sender"] ["blka@bla.com"]) {
    reject text:
noreply
============================
Your email has been canceled
============================
.
;
    stop;
} else {
    reject text:
================================
Your email has been canceled too
================================
.
;
}
