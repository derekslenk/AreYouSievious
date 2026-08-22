require ["body", "fileinto"];

if body :content "text" :contains ["missile", "coordinates"] {
    fileinto "secrets";
}
