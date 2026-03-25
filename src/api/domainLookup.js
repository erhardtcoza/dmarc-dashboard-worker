
import { dnsQuery } from "../dns/dnsLookup.js"

export async function lookupDomain(domain){

const spf=await dnsQuery(domain,"TXT")
const dmarc=await dnsQuery("_dmarc."+domain,"TXT")
const mx=await dnsQuery(domain,"MX")

const records={
spf:spf.map(x=>x.data),
dmarc:dmarc.map(x=>x.data),
mx:mx.map(x=>x.data)
}

const issues=[]

if(!records.spf.length) issues.push("SPF missing")
if(records.spf.length>1) issues.push("Multiple SPF records")
if(!records.dmarc.length) issues.push("DMARC missing")

return{domain,records,issues}

}
