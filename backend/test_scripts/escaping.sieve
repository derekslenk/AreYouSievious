require ["fileinto"];

# --- a quote inside a value and inside a folder name ---
if header :contains "subject" "she said \"hello\"" {
    fileinto "Quoted \"Folder\"";
}

# --- a backslash inside a value and inside a folder name ---
if header :is "x-source" "C:\\mail\\in" {
    fileinto "Windows\\Path";
}
