require ["enotify", "fileinto", "variables"];

if header :contains "from" "boss@example.org" {
    notify :importance "1"
        :message "This is probably very important"
                    "mailto:alm@example.com";
    # Don't send any further notifications
    stop;
}
