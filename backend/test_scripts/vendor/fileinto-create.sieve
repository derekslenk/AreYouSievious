require ["fileinto", "mailbox"];
if header :is "Sender" "owner-ietf-mta-filters@imc.org"
        {
        fileinto :create "filter";  # move to "filter" mailbox
        }
