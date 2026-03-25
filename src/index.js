export default {

async fetch(request, env) {

const url = new URL(request.url)

if (url.pathname === "/api/summary") return json(await getSummary(env))
if (url.pathname === "/api/timeline") return json(await getTimeline(env))
if (url.pathname === "/api/senders") return json(await getSenders(env))
if (url.pathname === "/api/domains") return json(await getDomains(env))
if (url.pathname === "/api/reputation") return json(await getReputation(env))
if (url.pathname === "/api/live_attack") return json(await getLiveAttack(env))

if (url.pathname === "/api/domain_lookup") {
const domain = url.searchParams.get("domain")
return json(await lookupDomain(env,domain))
}

if (url.pathname === "/api/bulk_lookup") {
const domains = url.searchParams.get("domains").split(",")
return json(await bulkLookup(env,domains))
}

return new Response(html,{
headers:{ "content-type":"text/html"}
})

}

}

function json(data){
return new Response(JSON.stringify(data),{
headers:{ "content-type":"application/json"}
})
}

async function dnsQuery(name,type){

const url="https://cloudflare-dns.com/dns-query?name="+name+"&type="+type

const r=await fetch(url,{headers:{accept:"application/dns-json"}})

const j=await r.json()

return j.Answer || []

}

async function lookupDomain(env,domain){

if(!domain) return {}

const spf = await dnsQuery(domain,"TXT")
const dmarc = await dnsQuery("_dmarc."+domain,"TXT")
const mx = await dnsQuery(domain,"MX")

let spfStatus="missing"
let dmarcStatus="missing"
let dkimStatus="missing"
let mxStatus="missing"

spf.forEach(r=>{
if(r.data.includes("v=spf1")) spfStatus="valid"
})

dmarc.forEach(r=>{
if(r.data.includes("p=reject")) dmarcStatus="reject"
else if(r.data.includes("p=quarantine")) dmarcStatus="quarantine"
else dmarcStatus="none"
})

if(mx.length>0) mxStatus="valid"

const selectors=["selector1","selector2","default","google"]

for(const s of selectors){

const r=await dnsQuery(s+"._domainkey."+domain,"TXT")

if(r.length>0){
dkimStatus="detected"
break
}

}

let issues=[]

if(spfStatus==="missing") issues.push("SPF missing")
if(dmarcStatus==="none") issues.push("DMARC policy none")
if(dkimStatus==="missing") issues.push("DKIM missing")

return {
domain,
spf:spfStatus,
dkim:dkimStatus,
dmarc:dmarcStatus,
mx:mxStatus,
issues
}

}

async function bulkLookup(env,domains){

const results=[]

for(const d of domains){

const r=await lookupDomain(env,d.trim())

results.push(r)

}

return results

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

const r=await env.DB.prepare(`

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

const r=await env.DB.prepare(`

SELECT source_ip,SUM(count) total
FROM dmarc_records
GROUP BY source_ip
ORDER BY total DESC
LIMIT 10

`).all()

return r.results

}

async function getDomains(env){

const r=await env.DB.prepare(`

SELECT domain,SUM(count) total
FROM dmarc_records
GROUP BY domain
ORDER BY total DESC

`).all()

return r.results

}

async function getLiveAttack(env){

const r=await env.DB.prepare(`

SELECT source_ip,SUM(count) failures
FROM dmarc_records
WHERE disposition!='none'
GROUP BY source_ip
ORDER BY failures DESC
LIMIT 1

`).first()

return r || {}

}

async function getReputation(env){

const rows=await env.DB.prepare(`

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

let reputation="Neutral"

if(r.failures===0) reputation="Trusted"
if(r.failures>20) reputation="Suspicious"
if(r.failures>100) reputation="Malicious"

out.push({
ip:r.source_ip,
total:r.total,
failures:r.failures,
reputation
})

})

return out

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
padding:15px 25px;
display:flex;
align-items:center;
gap:15px;
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
box-shadow:0 2px 6px rgba(0,0,0,0.08);
}

.metric{
font-size:36px;
font-weight:bold;
color:#e30613;
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

.alert{
background:#ffe8e8;
border-left:5px solid #e30613;
padding:12px;
margin-bottom:20px;
display:none;
font-weight:bold;
}

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

<br><br>

<textarea id="bulkDomains" placeholder="example.com&#10;vinet.co.za"></textarea>

<button onclick="bulkScan()">Bulk Scan</button>

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

</div>

<script>

async function scanDomain(){

const domain=document.getElementById("domainInput").value

const r=await fetch("/api/domain_lookup?domain="+domain)

const d=await r.json()

renderResults([d])

}

async function bulkScan(){

const raw=document.getElementById("bulkDomains").value

const domains=raw.split("\\n").join(",")

const r=await fetch("/api/bulk_lookup?domains="+domains)

const d=await r.json()

renderResults(d)

}

function renderResults(data){

let html="<table><tr><th>Domain</th><th>SPF</th><th>DKIM</th><th>DMARC</th><th>MX</th><th>Issues</th></tr>"

data.forEach(d=>{

html+="<tr>"
html+="<td>"+d.domain+"</td>"
html+="<td>"+d.spf+"</td>"
html+="<td>"+d.dkim+"</td>"
html+="<td>"+d.dmarc+"</td>"
html+="<td>"+d.mx+"</td>"
html+="<td>"+d.issues.length+"</td>"
html+="</tr>"

})

html+="</table>"

domainResult.innerHTML=html

}

async function loadAlert(){

const r=await fetch("/api/live_attack")

const d=await r.json()

if(d.failures>50){

alert.style.display="block"

alert.innerHTML="⚠ Active Spoof Attempt — IP "+d.source_ip+" ("+d.failures+" failures)"

}

}

async function loadReputation(){

const r=await fetch("/api/reputation")

const d=await r.json()

let html="<tr><th>IP</th><th>Total</th><th>Failures</th><th>Status</th></tr>"

d.forEach(x=>{

let cls="good"

if(x.reputation==="Suspicious") cls="warn"
if(x.reputation==="Malicious") cls="bad"

html+="<tr>"
html+="<td>"+x.ip+"</td>"
html+="<td>"+x.total+"</td>"
html+="<td>"+x.failures+"</td>"
html+="<td class='"+cls+"'>"+x.reputation+"</td>"
html+="</tr>"

})

reputation.innerHTML=html

}

async function chart(endpoint,canvas,label){

const r=await fetch(endpoint)

const d=await r.json()

new Chart(canvas,{
type:'bar',
data:{
labels:d.map(x=>x.day||x.source_ip||x.domain),
datasets:[{
label:label,
data:d.map(x=>x.total),
backgroundColor:"#e30613"
}]
}
})

}

loadAlert()
loadReputation()

chart("/api/timeline",timeline,"Emails")
chart("/api/senders",senders,"Senders")
chart("/api/domains",domains,"Domains")

</script>

</body>

</html>

`
