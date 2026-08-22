require ["fileinto"];

# --- the whole rule on one line ---
if header :is "subject" "ping" { fileinto "Ping"; }

# --- tabs and run-on spacing ---
if	allof (
	header    :contains    "from"    "ops@example.com",
	header :is "x-env" "prod"
)	{
	fileinto "Ops";
}
