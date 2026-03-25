export default {

async fetch(request, env) {

const url = new URL(request.url)

if (url.pathname === "/api/summary") return Response.json(await getSummary(env))
if (url.pathname === "/api/timeline") return Response.json(await getTimeline(env))
if (url.pathname === "/api/senders") return Response.json(await getSenders(env))
if (url.pathname === "/api/domains") return Response.json(await getDomains(env))
if (url.pathname === "/api/failures") return Response.json(await getFailures(env))
if (url.pathname === "/api/countries") return Response.json(await getCountries(env))
if (url.pathname === "/api/asn") return Response.json(await getASN(env))
if (url.pathname === "/api/map") return Response.json(await getMap(env))
if (url.pathname === "/api/spoof") return Response.json(await detectSpoof(env))
if (url.pathname === "/api/alerts") return Response.json(await getAlerts(env))

return new Response(html,{
headers:{ "content-type":"text/html"}
})

}

}

async function getSummary(env){

return await env.DB.prepare(`SELECT
SUM(count) as total,
SUM(CASE WHEN spf='pass' THEN count ELSE 0 END) as spf_pass,
SUM(CASE WHEN dkim='pass' THEN count ELSE 0 END) as dkim_pass,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) as failures
FROM dmarc_records`).first()

}

async function getTimeline(env){

const r = await env.DB.prepare(`SELECT
date(created_at/1000,'unixepoch') as day,
SUM(count) as total
FROM dmarc_records
GROUP BY day
ORDER BY day`).all()

return r.results

}

async function getSenders(env){

const r = await env.DB.prepare(`SELECT source_ip, SUM(count) as total
FROM dmarc_records
GROUP BY source_ip
ORDER BY total DESC
LIMIT 10`).all()

return r.results

}

async function getDomains(env){

const r = await env.DB.prepare(`SELECT domain, SUM(count) as total
FROM dmarc_records
GROUP BY domain
ORDER BY total DESC`).all()

return r.results

}

async function getFailures(env){

const r = await env.DB.prepare(`SELECT source_ip, spf, dkim, SUM(count) as total
FROM dmarc_records
WHERE disposition!='none'
GROUP BY source_ip
ORDER BY total DESC`).all()

return r.results

}

async function getCountries(env){

const senders = await env.DB.prepare(`SELECT source_ip, SUM(count) as total
FROM dmarc_records
GROUP BY source_ip`).all()

const results=[]

for(const s of senders.results){

let geo = await env.DB.prepare(
`SELECT * FROM ip_geo WHERE ip=?`
).bind(s.source_ip).first()

if(!geo){

const res = await fetch(`http://ip-api.com/json/${s.source_ip}`)
const data = await res.json()

await env.DB.prepare(`INSERT INTO ip_geo (ip,country,city,org,asn,lat,lon,last_checked)
VALUES (?,?,?,?,?,?,?,?)`)
.bind(
s.source_ip,
data.country,
data.city,
data.org,
data.as,
data.lat,
data.lon,
Date.now()
).run()

geo=data

}

results.push({
country:geo.country,
count:s.total
})

}

return results

}

async function getASN(env){

const r = await env.DB.prepare(`SELECT org, COUNT(*) as total
FROM ip_geo
GROUP BY org
ORDER BY total DESC
LIMIT 10`).all()

return r.results

}

async function getMap(env){

const r = await env.DB.prepare(`SELECT lat, lon
FROM ip_geo
WHERE lat IS NOT NULL
LIMIT 200`).all()

return r.results

}

async function detectSpoof(env){

const records = await env.DB.prepare(`SELECT source_ip, domain, spf, dkim, SUM(count) as total
FROM dmarc_records
WHERE disposition!='none'
GROUP BY source_ip
ORDER BY total DESC`).all()

const results=[]

for(const r of records.results){

let risk=0

if(r.spf !== 'pass') risk+=40
if(r.dkim !== 'pass') risk+=40
if(r.total > 50) risk+=20

if(risk >= 60){

await env.DB.prepare(`INSERT INTO spoof_events (
source_ip,
domain,
spf,
dkim,
count,
risk_score,
detected_at
)
VALUES (?,?,?,?,?,?,?)`)
.bind(
r.source_ip,
r.domain,
r.spf,
r.dkim,
r.total,
risk,
Date.now()
).run()

results.push({
ip:r.source_ip,
domain:r.domain,
risk:risk,
count:r.total
})

}

}

return results

}

async function getAlerts(env){

const summary = await getSummary(env)

const failureRate = summary.failures / summary.total

if(failureRate > 0.2){

await env.DB.prepare(`INSERT INTO alerts (type,message,created_at)
VALUES ('dmarc','High DMARC failure rate detected',?)`)
.bind(Date.now()).run()

}

const r = await env.DB.prepare(`SELECT * FROM alerts
ORDER BY created_at DESC
LIMIT 20`).all()

return r.results

}

const html = `

<html>

<head>

<title>DMARC Security Platform</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>

<link rel="stylesheet"
href="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css"/>

<style>

body{
background:#0f172a;
color:white;
font-family:system-ui;
margin:40px;
}

.grid{
display:grid;
grid-template-columns:repeat(4,1fr);
gap:20px;
margin-bottom:30px;
}

.card{
background:#1e293b;
padding:20px;
border-radius:12px;
}

canvas{
background:white;
border-radius:8px;
padding:10px;
}

#map{
height:400px;
border-radius:10px;
}

table{
width:100%;
border-collapse:collapse;
}

td,th{
padding:8px;
border-bottom:1px solid #333;
}

</style>

</head>

<body>

<h1>DMARC Security Platform</h1>

<div class="grid">

<div class="card"><h3>Total Emails</h3><div id="total"></div></div>
<div class="card"><h3>SPF Pass</h3><div id="spf"></div></div>
<div class="card"><h3>DKIM Pass</h3><div id="dkim"></div></div>
<div class="card"><h3>Failures</h3><div id="fail"></div></div>

</div>

<div class="card">
<h3>Email Timeline</h3>
<canvas id="timeline"></canvas>
</div>

<br>

<div class="card">
<h3>Top Senders</h3>
<canvas id="senders"></canvas>
</div>

<br>

<div class="card">
<h3>Sender Organizations</h3>
<canvas id="asn"></canvas>
</div>

<br>

<div class="card">
<h3>Global Email Sources</h3>
<div id="map"></div>
</div>

<br>

<div class="card">
<h3>Spoof Detection</h3>
<table id="spoofTable"></table>
</div>

<br>

<div class="card">
<h3>Security Alerts</h3>
<ul id="alerts"></ul>
</div>

<script>

async function loadSummary(){

const r = await fetch('/api/summary')
const d = await r.json()

total.innerHTML=d.total
spf.innerHTML=d.spf_pass
dkim.innerHTML=d.dkim_pass
fail.innerHTML=d.failures

}

async function loadTimeline(){

const r = await fetch('/api/timeline')
const d = await r.json()

new Chart(timeline,{
type:'line',
data:{
labels:d.map(x=>x.day),
datasets:[{label:'Emails',data:d.map(x=>x.total)}]
}
})

}

async function loadSenders(){

const r = await fetch('/api/senders')
const d = await r.json()

new Chart(senders,{
type:'bar',
data:{
labels:d.map(x=>x.source_ip),
datasets:[{label:'Emails',data:d.map(x=>x.total)}]
}
})

}

async function loadASN(){

const r = await fetch('/api/asn')
const d = await r.json()

new Chart(asn,{
type:'pie',
data:{
labels:d.map(x=>x.org),
datasets:[{data:d.map(x=>x.total)}]
}
})

}

async function loadMap(){

const r = await fetch('/api/map')
const d = await r.json()

const map = L.map('map').setView([20,0],2)

L.tileLayer(
'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png'
).addTo(map)

d.forEach(p=>{
L.marker([p.lat,p.lon]).addTo(map)
})

}

async function loadSpoof(){

const r = await fetch('/api/spoof')
const d = await r.json()

let html="<tr><th>IP</th><th>Domain</th><th>Risk</th><th>Emails</th></tr>"

d.forEach(x=>{
html+="<tr><td>"+x.ip+"</td><td>"+x.domain+"</td><td>"+x.risk+"</td><td>"+x.count+"</td></tr>"
})

spoofTable.innerHTML=html

}

async function loadAlerts(){

const r = await fetch('/api/alerts')
const d = await r.json()

alerts.innerHTML=""

d.forEach(a=>{
alerts.innerHTML+="<li>"+a.message+"</li>"
})

}

loadSummary()
loadTimeline()
loadSenders()
loadASN()
loadMap()
loadSpoof()
loadAlerts()

</script>

</body>
</html>

`
