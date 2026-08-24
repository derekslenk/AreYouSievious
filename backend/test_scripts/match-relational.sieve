require ["relational", "comparator-i;ascii-numeric", "fileinto"];

# --- spam score above a threshold ---
if header :value "gt" :comparator "i;ascii-numeric" "x-spam-score" "5" {
    fileinto "Junk";
}
