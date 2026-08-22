require ["fileinto", "envelope"];
require ["imap4flags"];

require [
    "copy",
    "reject"
];

# --- files and flags ---
if header :contains "subject" "report" {
    fileinto "Reports";
    addflag "\\Flagged";
}
