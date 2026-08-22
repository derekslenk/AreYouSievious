require ["fileinto"];

# routed by department
if header :is "x-dept" "sales" {
    fileinto "Sales";
} elsif header :is "x-dept" "support" {
    fileinto "Support";
} else {
    fileinto "Other";
}
