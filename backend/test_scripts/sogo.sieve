require ["fileinto"];
if allof (address :contains "from" "Paypal", header :contains "subject" "Receipt") {
    fileinto "Financials";
}
if allof (address :contains "from" "dan@nowiknow.com") {
    fileinto "nowiknow";
}
if allof (header :is "subject" "You have sold an item on the Community Market") {
    fileinto "Archives/Steam Sold Items";
}
if anyof (address :contains "from" "order-update@amazon.com", address :contains "from" "auto-confirm@amazon.com", address :contains "from" "USPSInformeddelivery@email.informeddelivery.usps.com", address :contains "from" "shipment-tracking@amazon.com", address :contains "from" "TrackingUpdates@fedex.com", address :contains "from" "auto-reply@usps.com", address :contains "from" "pkginfo@ups.com", address :contains "from" "mcinfo@ups.com") {
    fileinto "Mail and Packages";
}
if anyof (address :contains "from" "eps@alarmnet.com") {
    fileinto "Archives/EPS";
}
if allof (address :contains "from" "watchdog@mail.slenk.email") {
    fileinto "Watchdog";
}
if anyof (header :contains "subject" "WHMCS Domain Synchronisation Cron Report", header :contains "subject" "WHMCS Cron Job Activity") {
    fileinto "Gladiator/Cron Report";
}
if allof (header :contains "subject" "WHMCS Database Backup") {
    fileinto "Gladiator/DB Backups";
}
if allof (address :is "from" "dan@nowiknow.com") {
    fileinto "nowiknow";
}
if allof (header :contains "subject" "Your Verification Code", address :contains "from" "wisetack") {
    redirect "eslenk421@gmail.com";
    keep;
}
if anyof (address :contains "from" "*Uptime Kuma*", address :matches "to" "uptime-notifications@slenk.com") {
    fileinto "Daily Notifications/Uptime Kuma";
}
if allof (header :contains "subject" "ChangeDetection.io") {
    fileinto "Daily Notifications/Change Detection";
}
if allof (header :contains "subject" "BlacklistMaster") {
    fileinto "Daily Notifications/Blacklist Master";
}
if allof (address :is "from" "billing@linode.com") {
    fileinto "Financials/Linode";
}