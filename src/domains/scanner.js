import { dnsQuery } from "../dns/dnsLookup.js"
import { calculateHealth } from "./health.js"

export async function scanDomain(env,domain){

const spf = await dnsQuery(domain,"TXT")
const dmarc = await dnsQuery("_dmarc."+domain,"TXT")

const selectors=["selector1","selector2","default"]
let dkim=[]

for(const s of selectors){

const r = await dnsQuery(s+"._domainkey."+domain,"TXT")

if(r.length) dkim.push(...r)

}

const records={
spf:spf.map(x=>x.data),
dmarc:dmarc.map(x=>x.data),
dkim:dkim.map(x=>x.data)
}

const health = calculateHealth(records)

await env.DB.prepare(`
UPDATE domains
SET spf_status=?,
dkim_status=?,
dmarc_status=?,
health_score=?,
last_scan=?
WHERE domain=?
`)
.bind(
records.spf.length?"pass":"fail",
records.dkim.length?"pass":"fail",
records.dmarc.length?"pass":"fail",
health.score,
Date.now(),
domain
)
.run()

return {records,health}

}
