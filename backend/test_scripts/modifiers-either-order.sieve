require ["fileinto"];

# --- comparator before address-part ---
if address :comparator "i;ascii-casemap" :domain :is "from" "example.com" {
    fileinto "Example";
}

# --- address-part before comparator ---
if address :domain :comparator "i;ascii-casemap" :is "from" "example.net" {
    fileinto "Example Net";
}
