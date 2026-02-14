require ["fileinto", "envelope", "regex"];

# ============================================
# Grak Email Filters for derek@slenk.com
# Auto-generated 2026-02-14
# ============================================

# --- DOMAINS & INFRASTRUCTURE ---
if anyof (
    address :contains "from" "porkbun.com",
    address :contains "from" "gandi.net",
    address :contains "from" "namecheap.com",
    address :contains "from" "godaddy.com"
) {
    fileinto "Financials/Domains";
}

if anyof (
    address :contains "from" "cloudflare.com",
    address :contains "from" "hetzner.de",
    address :contains "from" "hetzner.com",
    address :contains "from" "bunny.net",
    address :contains "from" "digitalocean.com",
    address :contains "from" "zerossl.com",
    address :contains "from" "servercow.de",
    address :contains "from" "no-reply@slenk.com",
    address :contains "from" "noreply@slenk.network"
) {
    fileinto "Notifications/Infrastructure";
}

# --- GITHUB ---
if anyof (
    address :contains "from" "notifications@github.com",
    address :contains "from" "noreply@github.com"
) {
    fileinto "Notifications/GitHub";
}

# --- PODCASTS & PATREON ---
if anyof (
    address :contains "from" "patreon.com",
    address :contains "from" "memberfulmail.com"
) {
    fileinto "Subscriptions/Podcasts";
}

# --- NEWSLETTERS ---
if anyof (
    address :contains "from" "xda-developers.com",
    address :contains "from" "thangs.com",
    address :contains "from" "brevilabs.com",
    address :contains "from" "gasbuddy.com"
) {
    fileinto "Newsletters";
}

# --- AI / DEV TOOLS ---
if anyof (
    address :contains "from" "anthropic.com",
    address :contains "from" "openai.com",
    address :contains "from" "openbb.co"
) {
    fileinto "Notifications/AI";
}

# --- FINANCIAL ALERTS ---
if anyof (
    address :contains "from" "rocketmoney.com",
    address :contains "from" "creditkarma.com",
    address :contains "from" "empower.com",
    address :contains "from" "synchronybank.com",
    address :contains "from" "citi.com"
) {
    fileinto "Financials/Alerts";
}

# --- RECRUITING ---
if anyof (
    address :contains "from" "inmail-hit-reply@linkedin.com",
    address :contains "from" "jobs-listings@linkedin.com"
) {
    fileinto "Recruiting";
}

# --- GAMING ---
if anyof (
    address :contains "from" "epicgames.com",
    address :contains "from" "humblebundle.com",
    address :contains "from" "steampowered.com",
    address :contains "from" "gog.com",
    address :contains "from" "nintendo.com"
) {
    fileinto "Subscriptions/Gaming";
}

# --- STREAMING / ENTERTAINMENT ---
if anyof (
    address :contains "from" "netflix.com",
    address :contains "from" "hulu.com",
    address :contains "from" "spotify.com",
    address :contains "from" "twitch.tv"
) {
    fileinto "Subscriptions/Entertainment";
}

# --- GLADIATOR (extend existing) ---
if anyof (
    header :contains "subject" "WHMCS New Order Notification",
    header :contains "subject" "WHMCS Order Confirmation"
) {
    fileinto "Gladiator/New Orders";
}

if header :contains "subject" "WHMCS Successful Payment Confirmation" {
    fileinto "Gladiator/Success";
}

# ============================================
# EXISTING FILTERS (preserved from sogo)
# ============================================
# (original require merged above)
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