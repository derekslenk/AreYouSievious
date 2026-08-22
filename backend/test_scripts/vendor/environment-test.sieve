require ["environment", "fileinto"];
if environment :matches "remote_ip" "192.168.*" {
    fileinto "INBOX.Unsafe_Emails";
    stop;
}
