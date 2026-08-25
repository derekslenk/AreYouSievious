/* A bracketed comment before anything else in the file — the preamble
   boundary, which is the easiest place to get the span wrong
   (areyousievious-hr6). */

# --- drop the noisy list ---
if header :contains "list-id" "noise.example.com" { discard; }
