require ["date", "relational"];

if allof(currentdate :value "ge" "date" "2013-10-23",
         currentdate :value "le" "date" "2014-10-12")
{
    discard;
}
