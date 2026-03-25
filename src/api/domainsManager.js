import { dnsQuery } from "../dns/dnsLookup.js"

export async function addDomain(env,domain){

await env.DB.prepare(`INSERT OR IGNORE INTO domains(domain,added_at)
VALUES(?,?)`).bind(domain,Date.now()).run()

return {status:"added",domain}

}

export async function listDomains(env){

const r = await env.DB.prepare(`SELECT * FROM domains
ORDER BY domain`).all()

return r.results

}

export async function scanDomain(env,domain){

const spf = await dnsQuery(domain,"TXT")
const dmarc = await dnsQuery("_dmarc."+domain,"TXT")
const mx = await dnsQuery(domain,"MX")

let score = 100

if(!spf.length) score -= 30
if(!dmarc.length) score -= 40
if(!mx.length) score -= 20

await env.DB.prepare(`UPDATE domains
SET
spf=?,
dmarc=?,
mx=?,
score=?,
last_scan=?
WHERE domain=?`).bind(
JSON.stringify(spf),
JSON.stringify(dmarc),
JSON.stringify(mx),
score,
Date.now(),
domain
).run()

return{
domain,
spf,
dmarc,
mx,
score
}

}
