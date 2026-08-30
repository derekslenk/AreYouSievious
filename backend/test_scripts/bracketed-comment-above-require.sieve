/* Copyright (c) 2026 Example Ltd.
   Redistribution permitted under the terms of the MIT licence.

   A bracketed comment is not a command (RFC 5228 §2.3), so the `require`
   below still sits in the position §3.2 demands — but it is no longer the
   first thing the parser reaches, so it becomes a RawBlock and its
   extensions go unharvested (areyousievious-3xk). */


require ["fileinto", "imap4flags"];

# --- release notes ---
if header :contains "subject" "release notes" {
    fileinto "Releases";
    addflag "\\Seen";
}

# --- drop the build chatter ---
if header :contains "from" "ci@example.com" {
    discard;
}
