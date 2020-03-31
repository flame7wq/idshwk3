module HTTP;

@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

global p:table[addr] of set[string]={};

event http_reply(c:connection, version:string, code: count, reson:string)
{   
    for (k in c$id$resp_h)
        if (k !in p)
            p[k]=[to_lower(c$id$user_agent)];
        else
            add p[k][to_lower(c$id$user_agent)];
}

event zeek_init()
{
    for ( k in p)
        if (|p[k]|>=3)
            print fmt("%s is a proxy", k);
}


