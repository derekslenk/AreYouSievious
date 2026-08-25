require ["comparator-i;ascii-numeric", "fileinto"];

# --- numeric comparator needs a require ---
if header :comparator "i;ascii-numeric" :is "x-priority" "1" {
    fileinto "Urgent";
}
