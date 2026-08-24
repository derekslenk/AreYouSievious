require ["relational", "fileinto"];

# --- a relational test: string ordering, not numeric ---
if header :value "gt" :comparator "i;ascii-casemap" "x-batch" "m" {
    fileinto "Late Batch";
}
