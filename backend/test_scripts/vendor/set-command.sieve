require ["variables"];

set "matchsub" "testsubject";

if allof (
  header :contains ["Subject"] "${header}"
)
{
  discard;
}
