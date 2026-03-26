import { getTimeline } from "./api/timeline.js"
import { getSenders } from "./api/senders.js"
import { getDomains } from "./api/domains.js"

import { addDomain, listDomains, removeDomain, scanDomain } from "./api/domainsManager.js"

import { getReputation } from "./api/reputation.js"
import { getLiveAttack } from "./api/liveAttack.js"

import { getIPDetails, getDomainDetails, getDayDetails } from "./api/drilldown.js"

import { lookupDomain } from "./api/domainLookup.js"

import { explainAI } from "./ai/explain.js"

import html from "./ui/dashboard.html"


export default {

async fetch(request, env){

try {

const url = new URL(request.url)
const method = request.method

// ------------------------
// Analytics APIs
// ------------------------

if(url.pathname === "/api/timeline")
return json(await getTimeline(env))

if(url.pathname === "/api/senders")
return json(await getSenders(env))

if(url.pathname === "/api/domains")
return json(await getDomains(env))

if(url.pathname === "/api/reputation")
return json(await getReputation(env))

if(url.pathname === "/api/live_attack")
return json(await getLiveAttack(env))


// ------------------------
// Domain Management
// ------------------------

if(url.pathname === "/api/domains/list")
return json(await listDomains(env))

if(url.pathname === "/api/domains/add" && method === "POST"){

const body = await request.json()

return json(await addDomain(env, body.domain))

}

if(url.pathname === "/api/domains/remove" && method === "POST"){

const body = await request.json()

return json(await removeDomain(env, body.domain))

}

if(url.pathname === "/api/domains/scan")
return json(await scanDomain(env, url.searchParams.get("domain")))


// ------------------------
// Drilldown APIs
// ------------------------

if(url.pathname === "/api/ip")
return json(await getIPDetails(env, url.searchParams.get("ip")))

if(url.pathname === "/api/domain")
return json(await getDomainDetails(env, url.searchParams.get("domain")))

if(url.pathname === "/api/day")
return json(await getDayDetails(env, url.searchParams.get("day")))


// ------------------------
// DNS Lookup
// ------------------------

if(url.pathname === "/api/domain_lookup")
return json(await lookupDomain(url.searchParams.get("domain")))


// ------------------------
// AI Explain
// ------------------------

if(url.pathname === "/api/ai_explain" && method === "POST"){

const data = await request.json()

return json({
text: await explainAI(env, data)
})

}


// ------------------------
// Dashboard UI
// ------------------------

return new Response(html, {
headers: {
"content-type":"text/html"
}
})

}
catch(err){

return new Response(JSON.stringify({
error: err.message
}),{
status:500,
headers:{
"content-type":"application/json"
}
})

}

},


// ------------------------
// Scheduled Domain Scanning
// ------------------------

async scheduled(event, env, ctx){

const domains = await listDomains(env)

for(const d of domains){

await scanDomain(env, d.domain)

}

}

}



// ------------------------
// JSON Helper
// ------------------------

function json(data){

return new Response(
JSON.stringify(data),
{
headers:{
"content-type":"application/json",
"access-control-allow-origin":"*"
}
})

}
