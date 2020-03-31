global x:table[addr] of count={[1.1.1.6]=4};

global y:addr = 1.1.1.3;

global ip_count:table[count] of table[addr] of count={};
global p:table[addr] of set[string]={[1.1.1.7]=set("1","2","3","6")};

global m:string = "user-agent:1";
global n:string = "user-agent:2";

global num:set[string]={"1","2","3"};

event zeek_init()
    {

add p[1.1.1.7]["4"];
print |num|;
print |p[1.1.1.7]|;

if (y !in p)
    p[y]=[m];
if (y in p)
    add p[y][n];

print |p|;
print |p[1.1.1.3]|;
    if (y !in x)
        x[y]=1;
    else
        x[y]=x[y]+1;

        for (k in x)
                print fmt("%s is a proxy", k);
    }

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
        if (k in p)
            add p[k][to_lower(c$id$user_agent)];
}

event zeek_init()
{
    for ( k in p)
        if (|p[k]|>=3)
            print fmt("%s is a proxy", k);
}

module HTTP;
@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

global p:table[addr] of set[string]={};

global y:addr = 1.1.1.3;
global m:string = "user-agent:1";
global n:string = "user-agent:2";

global ip:set[addr]={[1.1.1.3],[1.1.1.2],[1.1.1.1],[1.1.1.4]};

event zeek_init()
{

    for (k in ip)
        if (k !in p)
            p[k]=[to_lower(m)];
        else
            add p[k][to_lower(n)];
    for ( k in p)
        if (|p[k]|>=1)
            print fmt("%s is a proxy", k);
    print p;
}


