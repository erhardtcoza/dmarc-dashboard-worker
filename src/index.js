import { getTimeline } from "./api/timeline"
import { getSenders } from "./api/senders"
import { getDomains } from "./api/domains"
import { getReputation } from "./api/reputation"
import { getLiveAttack } from "./api/liveAttack"
import { getIPDetails,getDomainDetails,getDayDetails } from "./api/drilldown"
import { lookupDomain } from "./api/domainLookup"
import { explainAI } from "./ai/explain"
import html from "./ui/dashboard.html"

export default {

async fetch(request, env){

const url = new URL(request.url)

if(url.pathname==="/api/timeline")
return json(await getTimeline(env))

if(url.pathname==="/api/senders")
return json(await getSenders(env))

if(url.pathname==="/api/domains")
return json(await getDomains(env))

if(url.pathname==="/api/reputation")
return json(await getReputation(env))

if(url.pathname==="/api/live_attack")
return json(await getLiveAttack(env))

if(url.pathname==="/api/ip")
return json(await getIPDetails(env,url.searchParams.get("ip")))

if(url.pathname==="/api/domain")
return json(await getDomainDetails(env,url.searchParams.get("domain")))

if(url.pathname==="/api/day")
return json(await getDayDetails(env,url.searchParams.get("day")))

if(url.pathname==="/api/domain_lookup")
return json(await lookupDomain(url.searchParams.get("domain")))

if(url.pathname==="/api/ai_explain"){
const data = await request.json()
return json({text:await explainAI(env,data)})
}

return new Response(html,{
headers:{"content-type":"text/html"}
})

}

}

function json(data){
return new Response(JSON.stringify(data),{
headers:{"content-type":"application/json"}
})
}
