export default {

async fetch(request, env) {

const url = new URL(request.url)

if (url.pathname === "/api/summary") return json(await getSummary(env))
if (url.pathname === "/api/timeline") return json(await getTimeline(env))
if (url.pathname === "/api/providers") return json(await getProviders(env))
if (url.pathname === "/api/senders") return json(await getSenders(env))
if (url.pathname === "/api/domains") return json(await getDomains(env))
if (url.pathname === "/api/map") return json(await getMap(env))
if (url.pathname === "/api/score") return json(await calculateScore(env))
if (url.pathname === "/api/attack_timeline") return json(await getAttackTimeline(env))
if (url.pathname === "/api/domain_scan") return json(await scanDomain("vinet.co.za"))
if (url.pathname === "/api/live_attack") return json(await getLiveAttack(env))
if (url.pathname === "/api/reputation") return json(await getReputation(env))

return new Response(html,{headers:{ "content-type":"text/html"}})

}

}

function json(data){
return new Response(JSON.stringify(data),{
headers:{ "content-type":"application/json"}
})
}

async function dnsQuery(name,type){

const url="https://cloudflare-dns.com/dns-query?name="+name+"&type="+type

const res=await fetch(url,{headers:{accept:"application/dns-json"}})

const data=await res.json()

return data.Answer || []

}

async function scanDomain(domain){

const spfRecords=await dnsQuery(domain,"TXT")
const dmarcRecords=await dnsQuery("_dmarc."+domain,"TXT")
const bimiRecords=await dnsQuery("default._bimi."+domain,"TXT")
const mxRecords=await dnsQuery(domain,"MX")

let spf="missing"
let dmarc="missing"
let bimi="missing"
let mx="missing"
let dkim="missing"

spfRecords.forEach(r=>{
if(r.data.includes("v=spf1")) spf="valid"
})

dmarcRecords.forEach(r=>{
if(r.data.includes("p=reject")) dmarc="reject"
else if(r.data.includes("p=quarantine")) dmarc="quarantine"
else dmarc="none"
})

if(bimiRecords.length>0) bimi="detected"
if(mxRecords.length>0) mx="valid"

const selectors=["selector1","selector2","default","google","k1","mail"]

for(const s of selectors){

const result = await dnsQuery(s+"._domainkey."+domain,"TXT")

if(result.length>0){
dkim="detected"
break
}

}

let compliance=0

if(spf==="valid") compliance+=25
if(dkim==="detected") compliance+=25
if(dmarc==="reject") compliance+=25
if(bimi==="detected") compliance+=25

return {spf,dmarc,dkim,bimi,mx,compliance}

}

async function getSummary(env){

return await env.DB.prepare(`SELECT
SUM(count) total,
SUM(CASE WHEN spf='pass' THEN count ELSE 0 END) spf_pass,
SUM(CASE WHEN dkim='pass' THEN count ELSE 0 END) dkim_pass,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records`).first()

}

async function getTimeline(env){

const r=await env.DB.prepare(`SELECT date(created_at/1000,'unixepoch') day,
SUM(count) total
FROM dmarc_records
GROUP BY day
ORDER BY day`).all()

return r.results

}

async function getSenders(env){

const r=await env.DB.prepare(`SELECT source_ip, SUM(count) total
FROM dmarc_records
GROUP BY source_ip
ORDER BY total DESC
LIMIT 10`).all()

return r.results

}

async function getDomains(env){

const r=await env.DB.prepare(`SELECT domain, SUM(count) total
FROM dmarc_records
GROUP BY domain
ORDER BY total DESC`).all()

return r.results

}

async function getProviders(env){

const r=await env.DB.prepare(`SELECT org, COUNT(*) total
FROM ip_geo
GROUP BY org`).all()

return r.results

}

async function getMap(env){

const r=await env.DB.prepare(`SELECT lat,lon
FROM ip_geo
WHERE lat IS NOT NULL
LIMIT 200`).all()

return r.results

}

async function getAttackTimeline(env){

const r=await env.DB.prepare(`SELECT date(detected_at/1000,'unixepoch') day,
COUNT(*) attacks
FROM spoof_events
GROUP BY day`).all()

return r.results

}

async function getLiveAttack(env){

const r=await env.DB.prepare(`

SELECT source_ip,
SUM(count) failures
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

const results=[]

rows.results.forEach(r=>{

let reputation="Neutral"

if(r.failures===0) reputation="Trusted"
if(r.failures>20) reputation="Suspicious"
if(r.failures>100) reputation="Malicious"

results.push({
ip:r.source_ip,
total:r.total,
failures:r.failures,
reputation
})

})

return results

}

async function calculateScore(env){

const stats=await getSummary(env)

if(!stats.total) return {score:0}

const spfRate=stats.spf_pass/stats.total
const dkimRate=stats.dkim_pass/stats.total
const failureRate=stats.failures/stats.total

let score=100

score -= (1-spfRate)*30
score -= (1-dkimRate)*30
score -= failureRate*40

return {score:Math.round(score)}

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
max-width:1600px;
margin:auto;
padding:25px;
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
box-shadow:0 1px 4px rgba(0,0,0,0.08);
}

.metric{
font-size:36px;
font-weight:bold;
color:#e30613;
}

table{
width:100%;
border-collapse:collapse;
}

td,th{
padding:6px;
border-bottom:1px solid #ddd;
font-size:13px;
}

.bad{color:red;font-weight:bold}
.warn{color:orange;font-weight:bold}
.good{color:green;font-weight:bold}

canvas{
height:200px!important;
}

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

<div class="grid">

<div class="card">
<h3>Security Score</h3>
<div id="score" class="metric"></div>
</div>

<div class="card">
<h3>DMARC Compliance</h3>
<div id="compliance" class="metric"></div>
</div>

<div class="card">
<h3>Email Authentication</h3>
<ul id="scan"></ul>
</div>

<div class="card">
<h3>Email Timeline</h3>
<canvas id="timeline"></canvas>
</div>

<div class="card">
<h3>Spoof Attacks</h3>
<canvas id="attacks"></canvas>
</div>

<div class="card">
<h3>Providers</h3>
<canvas id="providers"></canvas>
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

function animateValue(el,end){

let start=0
let step=end/20

function update(){

start+=step

if(start>=end){
el.innerHTML=end
return
}

el.innerHTML=Math.round(start)

requestAnimationFrame(update)

}

update()

}

async function loadScore(){

const r=await fetch('/api/score')
const d=await r.json()

animateValue(score,d.score)

}

async function loadScan(){

const r=await fetch('/api/domain_scan')
const d=await r.json()

scan.innerHTML=""

scan.innerHTML+="<li>SPF: "+d.spf+"</li>"
scan.innerHTML+="<li>DMARC: "+d.dmarc+"</li>"
scan.innerHTML+="<li>DKIM: "+d.dkim+"</li>"
scan.innerHTML+="<li>BIMI: "+d.bimi+"</li>"
scan.innerHTML+="<li>MX: "+d.mx+"</li>"

animateValue(compliance,d.compliance)

}

async function loadAlert(){

const r=await fetch('/api/live_attack')
const d=await r.json()

if(d.failures>50){

alert.style.display="block"

alert.innerHTML="⚠ Active Spoof Attempt Detected — IP "+d.source_ip+" ("+d.failures+" failed emails)"

}

}

async function loadReputation(){

const r=await fetch('/api/reputation')
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
labels:d.map(x=>x.day||x.source_ip||x.domain||x.org),
datasets:[{
label:label,
data:d.map(x=>x.total||x.attacks),
backgroundColor:"#e30613"
}]
},
options:{
plugins:{legend:{display:false}}
}
})

}

loadScore()
loadScan()
loadAlert()
loadReputation()

chart('/api/timeline',timeline,'Emails')
chart('/api/attack_timeline',attacks,'Spoof Attacks')
chart('/api/providers',providers,'Providers')
chart('/api/senders',senders,'Emails')
chart('/api/domains',domains,'Emails')

</script>

</body>
</html>

`
