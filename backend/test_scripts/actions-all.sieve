require ["copy", "fileinto", "imap4flags", "reject"];

# --- every quoted and bare action, in one block ---
if allof (
    header :contains "subject" "invoice"
) {
    fileinto "Invoices";
    fileinto :copy "Archive";
    redirect "billing@example.com";
    addflag "\\Seen";
    keep;
    stop;
}

# --- reject then discard ---
if header :is "from" "spam@example.net" {
    reject "This address does not accept unsolicited mail.";
    discard;
}
