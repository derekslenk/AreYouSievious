require ["fileinto", "imap4flags", "variables"];
if size :over 1M {
    addflag "MyFlags" "Big";
    if header :is "From" "boss@company.example.com" {
       # The message will be marked as "\Flagged Big" when filed into
       # mailbox "Big messages"
       addflag "MyFlags" "\\Flagged";
    }
    fileinto :flags "${MyFlags}" "Big messages";
}
