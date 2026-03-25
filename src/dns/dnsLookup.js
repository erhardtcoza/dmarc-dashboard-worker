export async function dnsQuery(name,type){

const r = await fetch(
"https://cloudflare-dns.com/dns-query?name="+name+"&type="+type,
{headers:{accept:"application/dns-json"}}
)

const j = await r.json()

return j.Answer || []

}
