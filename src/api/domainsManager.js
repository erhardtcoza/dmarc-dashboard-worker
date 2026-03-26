export async function addDomain(env, domain){

if(!domain) return {error:"domain required"}

await env.DB.prepare(`INSERT OR IGNORE INTO domains(domain,added_at)
VALUES(?,?)`)
.bind(domain, Date.now())
.run()

return {status:"added", domain}

}

export async function listDomains(env){

const r = await env.DB.prepare(`SELECT * FROM domains
ORDER BY domain`).all()

return r.results

}

export async function removeDomain(env, domain){

if(!domain) return {error:"domain required"}

await env.DB.prepare(`DELETE FROM domains
WHERE domain=?`)
.bind(domain)
.run()

return {status:"removed", domain}

}

export async function scanDomain(env, domain){

if(!domain) return {error:"domain required"}

const dns = await fetch(
"https://cloudflare-dns.com/dns-query?name="+domain+"&type=TXT",
{headers:{accept:"application/dns-json"}}
)

const txt = await dns.json()

const records = txt.Answer ? txt.Answer.map(x=>x.data) : []

await env.DB.prepare(`UPDATE domains
SET last_scan=?
WHERE domain=?`)
.bind(Date.now(),domain)
.run()

return {
domain,
records
}

}
