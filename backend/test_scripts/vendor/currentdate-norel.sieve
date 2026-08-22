require ["date"];

if allof (
  currentdate :zone "+0100" :is "date" "2013-10-23"
)
{
    discard;
}
