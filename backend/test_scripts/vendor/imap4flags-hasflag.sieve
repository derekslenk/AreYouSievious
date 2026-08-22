require ["imap4flags", "fileinto"];

if hasflag ["test", "toto"] {
    fileinto "Test";
}
addflag "Var1" "Truc";
if hasflag "Var1" "Truc" {
    fileinto "Truc";
}
