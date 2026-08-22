require ["fileinto", "reject"];

if allof (not allof (address :is ["From","sender"] ["test1@test2.priv","test2@test2.priv"], header :matches "Subject" "INACTIVE*"), address :is "From" "user3@test3.priv")
{
    reject;
}
