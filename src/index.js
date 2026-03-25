export default {

async fetch(request, env) {

const url = new URL(request.url)

if(url.pathname==="/api/summary") return json(await getSummary(env))
if(url.pathname==="/api/timeline") return json(await getTimeline(env))
if(url.pathname==="/api/senders") return json(await getSenders(env))
if(url.pathname==="/api/domains") return json(await getDomains(env))
if(url.pathname==="/api/reputation") return json(await getReputation(env))
if(url.pathname==="/api/live_attack") return json(await getLiveAttack(env))

if(url.pathname==="/api/day")
return json(await getDayDetails(env,url.searchParams.get("day")))

if(url.pathname==="/api/ip")
return json(await getIPDetails(env,url.searchParams.get("ip")))

if(url.pathname==="/api/domain")
return json(await getDomainDetails(env,url.searchParams.get("domain")))

if(url.pathname==="/api/domain_lookup")
return json(await lookupDomain(url.searchParams.get("domain")))

if(url.pathname==="/api/ai_explain"){
const data = await request.json()
return json({text:await explainAI(env,data)})
}

return new Response(html,{headers:{"content-type":"text/html"}})

}

}

function json(data){
return new Response(JSON.stringify(data),{
headers:{"content-type":"application/json"}
})
}

async function dnsQuery(name,type){

const r = await fetch(
"https://cloudflare-dns.com/dns-query?name="+name+"&type="+type,
{headers:{accept:"application/dns-json"}}
)

const j = await r.json()

return j.Answer || []

}

async function lookupDomain(domain){

const spf = await dnsQuery(domain,"TXT")
const dmarc = await dnsQuery("_dmarc."+domain,"TXT")
const mx = await dnsQuery(domain,"MX")
const bimi = await dnsQuery("default._bimi."+domain,"TXT")

const selectors=["selector1","selector2","google","default"]

let dkim=[]

for(const s of selectors){

const r = await dnsQuery(s+"._domainkey."+domain,"TXT")

if(r.length) dkim.push(...r.map(x=>x.data))

}

const records={
spf:spf.map(x=>x.data),
dmarc:dmarc.map(x=>x.data),
mx:mx.map(x=>x.data),
dkim:dkim,
bimi:bimi.map(x=>x.data)
}

const issues=[]

if(!records.spf.length) issues.push("SPF missing")
if(records.spf.length>1) issues.push("Multiple SPF records")

if(!records.dmarc.length) issues.push("DMARC missing")
if(records.dmarc[0]?.includes("p=none"))
issues.push("DMARC policy none")

if(!records.dkim.length) issues.push("DKIM not detected")

return{domain,records,issues}

}

async function getSummary(env){

return await env.DB.prepare(`

SELECT
SUM(count) total,
SUM(CASE WHEN spf='pass' THEN count ELSE 0 END) spf_pass,
SUM(CASE WHEN dkim='pass' THEN count ELSE 0 END) dkim_pass,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records

`).first()

}

async function getTimeline(env){

const r = await env.DB.prepare(`

SELECT
date(created_at/1000,'unixepoch') day,
SUM(count) total
FROM dmarc_records
GROUP BY day
ORDER BY day

`).all()

return r.results

}

async function getSenders(env){

const r = await env.DB.prepare(`

SELECT source_ip,SUM(count) total
FROM dmarc_records
GROUP BY source_ip
ORDER BY total DESC
LIMIT 10

`).all()

return r.results

}

async function getDomains(env){

const r = await env.DB.prepare(`

SELECT domain,SUM(count) total
FROM dmarc_records
GROUP BY domain
ORDER BY total DESC

`).all()

return r.results

}

async function getReputation(env){

const rows = await env.DB.prepare(`

SELECT
source_ip,
SUM(count) total,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records
GROUP BY source_ip
ORDER BY total DESC
LIMIT 10

`).all()

const out=[]

rows.results.forEach(r=>{

let status="Neutral"
let reason="Normal traffic"

if(r.failures>100){
status="Malicious"
reason=r.failures+" DMARC failures"
}

else if(r.failures>20){
status="Suspicious"
reason="High failure rate"
}

out.push({
ip:r.source_ip,
total:r.total,
failures:r.failures,
status,
reason
})

})

return out

}

async function getLiveAttack(env){

const r = await env.DB.prepare(`

SELECT source_ip,SUM(count) failures
FROM dmarc_records
WHERE disposition!='none'
GROUP BY source_ip
ORDER BY failures DESC
LIMIT 1

`).first()

return r || {}

}

async function getDayDetails(env,day){

const r = await env.DB.prepare(`

SELECT
source_ip,
domain,
SUM(count) total,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records
WHERE date(created_at/1000,'unixepoch')=?
GROUP BY source_ip,domain

`).bind(day).all()

return r.results

}

async function getIPDetails(env,ip){

const r = await env.DB.prepare(`

SELECT
domain,
SUM(count) total,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records
WHERE source_ip=?
GROUP BY domain

`).bind(ip).all()

return r.results

}

async function getDomainDetails(env,domain){

const r = await env.DB.prepare(`

SELECT
source_ip,
SUM(count) total,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records
WHERE domain=?
GROUP BY source_ip

`).bind(domain).all()

return r.results

}

async function explainAI(env,data){

if(!env.OPENAI_API_KEY)
return "AI not configured"

const r = await fetch("https://api.openai.com/v1/chat/completions",{

method:"POST",

headers:{
Authorization:"Bearer "+env.OPENAI_API_KEY,
"Content-Type":"application/json"
},

body:JSON.stringify({

model:"gpt-4o-mini",

messages:[
{
role:"system",
content:"Explain DMARC email authentication and potential spoofing issues."
},
{
role:"user",
content:JSON.stringify(data)
}
]

})

})

const j = await r.json()

return j.choices?.[0]?.message?.content || ""

}

const html = `

<html>
<head>

<title>Vinet DMARC Security Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

body{
font-family:system-ui;
margin:0;
background:#f4f6f9;
}

.header{
background:white;
border-bottom:3px solid #e30613;
padding:15px;
display:flex;
gap:10px;
}

.logo{height:36px}

.container{
max-width:1400px;
margin:auto;
padding:30px;
}

.grid{
display:grid;
grid-template-columns:repeat(3,1fr);
gap:20px;
}

.card{
background:white;
padding:20px;
border-radius:8px;
box-shadow:0 2px 6px rgba(0,0,0,.08);
}

.alert{
background:#ffe8e8;
border-left:5px solid #e30613;
padding:10px;
margin-bottom:20px;
display:none;
}

table{
width:100%;
border-collapse:collapse;
font-size:13px;
}

td,th{
padding:6px;
border-bottom:1px solid #eee;
}

.bad{color:red;font-weight:bold}
.warn{color:orange;font-weight:bold}
.good{color:green;font-weight:bold}

</style>

</head>

<body>

<div class="header">
<img src="https://static.vinet.co.za/logo.jpeg" class="logo">
<strong>Vinet DMARC Security Dashboard</strong>
</div>

<div class="container">

<div id="alert" class="alert"></div>

<div class="card">

<h3>Domain Analyzer</h3>

<input id="domainInput" placeholder="example.com">

<button onclick="scanDomain()">Scan</button>

<div id="domainResult"></div>

</div>

<div class="grid">

<div class="card">
<h3>Email Timeline</h3>
<canvas id="timeline"></canvas>
</div>

<div class="card">
<h3>Top Senders</h3>
<canvas id="senders"></canvas>
</div>

<div class="card">
<h3>Domains</h3>
<canvas id="domains"></canvas>
</div>

<div class="card">
<h3>Sender Reputation</h3>
<table id="reputation"></table>
</div>

</div>

<div class="card">

<h3>Detail View</h3>

<div id="detailTitle"></div>

<table id="detailTable"></table>

<button onclick="askAI()">Explain with AI</button>

<div id="aiText"></div>

</div>

</div>

<script>

let currentContext=null

async function scanDomain(){

const domain=document.getElementById("domainInput").value

const r=await fetch("/api/domain_lookup?domain="+domain)

const d=await r.json()

let html="<b>"+domain+"</b><br><br>"

html+="SPF:<br>"+d.records.spf.join("<br>")+"<br><br>"
html+="DKIM:<br>"+d.records.dkim.join("<br>")+"<br><br>"
html+="DMARC:<br>"+d.records.dmarc.join("<br>")+"<br><br>"
html+="MX:<br>"+d.records.mx.join("<br>")+"<br><br>"

if(d.issues.length){

html+="<b>Issues</b><br>"+d.issues.join("<br>")

}

domainResult.innerHTML=html

}

async function loadReputation(){

const r=await fetch("/api/reputation")

const d=await r.json()

let html="<tr><th>IP</th><th>Total</th><th>Failures</th><th>Status</th><th>Reason</th></tr>"

d.forEach(x=>{

let cls="good"

if(x.status==="Suspicious") cls="warn"
if(x.status==="Malicious") cls="bad"

html+="<tr onclick='loadIP(\""+x.ip+"\")'>"
html+="<td>"+x.ip+"</td>"
html+="<td>"+x.total+"</td>"
html+="<td>"+x.failures+"</td>"
html+="<td class='"+cls+"'>"+x.status+"</td>"
html+="<td>"+x.reason+"</td>"
html+="</tr>"

})

reputation.innerHTML=html

}

async function loadIP(ip){

detailTitle.innerHTML="IP "+ip

const r=await fetch("/api/ip?ip="+ip)

const d=await r.json()

currentContext=d

let html="<tr><th>Domain</th><th>Total</th><th>Failures</th></tr>"

d.forEach(x=>{
html+="<tr><td>"+x.domain+"</td><td>"+x.total+"</td><td>"+x.failures+"</td></tr>"
})

detailTable.innerHTML=html

}

async function askAI(){

const r=await fetch("/api/ai_explain",{method:"POST",body:JSON.stringify(currentContext)})

const j=await r.json()

aiText.innerHTML=j.text

}

async function checkAttack(){

const r=await fetch("/api/live_attack")

const d=await r.json()

if(d.failures>50){

alert.style.display="block"

alert.innerHTML="⚠ Possible spoof attack from "+d.source_ip+" ("+d.failures+" failures)"

}

}

checkAttack()

loadReputation()

</script>

</body>
</html>
`
