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
if (url.pathname === "/api/anomalies") return json(await detectAnomalies(env))
if (url.pathname === "/api/attack_timeline") return json(await getAttackTimeline(env))
if (url.pathname === "/api/domain_scan") return json(await scanDomain("vinet.co.za"))

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
let selector=""

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
selector=s
break
}

}

let compliance=0
if(spf==="valid") compliance+=25
if(dkim==="detected") compliance+=25
if(dmarc==="reject") compliance+=25
if(bimi==="detected") compliance+=25

return {domain,spf,dmarc,dkim,selector,bimi,mx,compliance}

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
const rows=await env.DB.prepare(`SELECT org, COUNT(*) total
FROM ip_geo
GROUP BY org`).all()
return rows.results
}

async function getMap(env){
const r=await env.DB.prepare(`SELECT lat,lon FROM ip_geo
WHERE lat IS NOT NULL
LIMIT 200`).all()
return r.results
}

async function getAttackTimeline(env){
const r=await env.DB.prepare(`SELECT date(detected_at/1000,'unixepoch') day,
COUNT(*) attacks
FROM spoof_events
GROUP BY day
ORDER BY day`).all()
return r.results
}

async function calculateScore(env){

const stats = await getSummary(env)

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

async function detectAnomalies(env){
return []
}

const html = `

<html>

<head>

<title>Vinet DMARC Security Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>

<link rel="stylesheet"
href="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css"/>

<style>

body{
background:#0f172a;
color:white;
font-family:system-ui;
margin:0;
}

.nav{
background:#0b0b0b;
border-bottom:3px solid #e30613;
padding:12px 25px;
display:flex;
align-items:center;
gap:15px;
}

.logo{height:32px}

.container{
padding:20px;
max-width:1600px;
margin:auto;
}

.grid{
display:grid;
grid-template-columns:repeat(4,1fr);
gap:15px;
}

.card{
background:#1e293b;
padding:15px;
border-radius:8px;
}

.card h3{
font-size:14px;
margin-bottom:10px;
color:#cbd5e1;
}

.score{
font-size:34px;
font-weight:bold;
color:#e30613;
}

canvas{
background:white;
border-radius:8px;
padding:6px;
height:220px!important;
}

#map{
height:220px;
border-radius:8px;
}

.span2{
grid-column:span 2;
}

.span4{
grid-column:span 4;
}

ul{
margin:0;
padding-left:18px;
}

</style>

</head>

<body>

<div class="nav">

<img src="https://static.vinet.co.za/logo.jpeg" class="logo">

<strong>Vinet DMARC Security Dashboard</strong>

</div>

<div class="container">

<div class="grid">

<div class="card">
<h3>Security Score</h3>
<div id="score" class="score"></div>
</div>

<div class="card">
<h3>DMARC Compliance</h3>
<div id="compliance" class="score"></div>
</div>

<div class="card span2">
<h3>Email Authentication</h3>
<ul id="scan"></ul>
</div>

<div class="card span2">
<h3>Email Timeline</h3>
<canvas id="timeline"></canvas>
</div>

<div class="card span2">
<h3>Spoof Attacks</h3>
<canvas id="attacks"></canvas>
</div>

<div class="card span2">
<h3>Providers</h3>
<canvas id="providers"></canvas>
</div>

<div class="card span2">
<h3>Top Senders</h3>
<canvas id="senders"></canvas>
</div>

<div class="card span2">
<h3>Domains</h3>
<canvas id="domains"></canvas>
</div>

<div class="card span2">
<h3>Global Sources</h3>
<div id="map"></div>
</div>

</div>

</div>

<script>

async function loadScore(){

const r=await fetch('/api/score')
const d=await r.json()

score.innerHTML=d.score

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

compliance.innerHTML=d.compliance+"%"

}

async function chart(endpoint,canvas,label){

const r=await fetch(endpoint)
const d=await r.json()

new Chart(canvas,{
type:'bar',
data:{
labels:d.map(x=>x.day||x.provider||x.source_ip||x.domain),
datasets:[{
label:label,
data:d.map(x=>x.total||x.attacks)
}]
}
})

}

async function loadMap(){

const r=await fetch('/api/map')
const d=await r.json()

const map=L.map('map').setView([20,0],2)

L.tileLayer(
'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png'
).addTo(map)

d.forEach(p=>{
L.marker([p.lat,p.lon]).addTo(map)
})

}

loadScore()
loadScan()

chart('/api/timeline',timeline,'Emails')
chart('/api/attack_timeline',attacks,'Spoof Attacks')
chart('/api/providers',providers,'Providers')
chart('/api/senders',senders,'Emails')
chart('/api/domains',domains,'Emails')

loadMap()

</script>

</body>
</html>

`
