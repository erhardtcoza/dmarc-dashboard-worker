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

async function getSummary(env){
return await env.DB.prepare(`SELECT
SUM(count) total,
SUM(CASE WHEN spf='pass' THEN count ELSE 0 END) spf_pass,
SUM(CASE WHEN dkim='pass' THEN count ELSE 0 END) dkim_pass,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records`).first()
}

async function getTimeline(env){
const r = await env.DB.prepare(`SELECT date(created_at/1000,'unixepoch') day,
SUM(count) total
FROM dmarc_records
GROUP BY day
ORDER BY day`).all()
return r.results
}

async function getSenders(env){
const r = await env.DB.prepare(`SELECT source_ip, SUM(count) total
FROM dmarc_records
GROUP BY source_ip
ORDER BY total DESC
LIMIT 10`).all()
return r.results
}

async function getDomains(env){
const r = await env.DB.prepare(`SELECT domain, SUM(count) total
FROM dmarc_records
GROUP BY domain
ORDER BY total DESC`).all()
return r.results
}

function classifyProvider(org){

if(!org) return "Unknown"

org=org.toLowerCase()

if(org.includes("google")) return "Google"
if(org.includes("microsoft")) return "Microsoft"
if(org.includes("amazon")) return "Amazon SES"
if(org.includes("sendgrid")) return "Sendgrid"
if(org.includes("mailgun")) return "Mailgun"

return "Other"

}

async function getProviders(env){

const rows = await env.DB.prepare(`SELECT org, COUNT(*) total
FROM ip_geo
GROUP BY org`).all()

const map={}

rows.results.forEach(r=>{
const p=classifyProvider(r.org)
map[p]=(map[p]||0)+r.total
})

return Object.keys(map).map(k=>{
return {provider:k,total:map}
})

}

async function getMap(env){
const r = await env.DB.prepare(`SELECT lat,lon FROM ip_geo
WHERE lat IS NOT NULL
LIMIT 200`).all()
return r.results
}

async function getAttackTimeline(env){
const r = await env.DB.prepare(`SELECT date(detected_at/1000,'unixepoch') day,
COUNT(*) attacks
FROM spoof_events
GROUP BY day
ORDER BY day`).all()
return r.results
}

async function calculateScore(env){

const stats = await getSummary(env)

if(!stats.total) return {score:0}

const spfRate = stats.spf_pass / stats.total
const dkimRate = stats.dkim_pass / stats.total
const failureRate = stats.failures / stats.total

let score = 100

score -= (1-spfRate)*30
score -= (1-dkimRate)*30
score -= failureRate*40

score = Math.round(score)

return {score}

}

async function detectAnomalies(env){

const recent = await env.DB.prepare(`SELECT SUM(count) total
FROM dmarc_records
WHERE created_at > strftime('%s','now','-1 day')*1000`).first()

const historical = await env.DB.prepare(`SELECT AVG(daily) avg
FROM (
SELECT date(created_at/1000,'unixepoch') day,
SUM(count) daily
FROM dmarc_records
GROUP BY day
)`).first()

const anomalies=[]

if(recent.total > historical.avg*2){

anomalies.push({
message:"Email traffic spike detected"
})

}

return anomalies

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

display:flex;
align-items:center;
gap:20px;
background:#0b0b0b;
padding:15px 30px;
border-bottom:3px solid #e30613;

}

.logo{
height:40px;
}

.container{
padding:30px;
}

.grid{
display:grid;
grid-template-columns:repeat(3,1fr);
gap:20px;
}

.card{
background:#1e293b;
padding:20px;
border-radius:10px;
}

.score{
font-size:50px;
color:#e30613;
font-weight:bold;
}

canvas{
background:white;
border-radius:10px;
padding:10px;
}

#map{
height:400px;
border-radius:10px;
}

</style>

</head>

<body>

<div class="nav">

<img src="https://static.vinet.co.za/logo.jpeg" class="logo">

<h2>Vinet DMARC Security Dashboard</h2>

</div>

<div class="container">

<div class="grid">

<div class="card">
<h3>Domain Security Score</h3>
<div id="score" class="score"></div>
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
<h3>Global Mail Sources</h3>
<div id="map"></div>
</div>

</div>

</div>

<script>

async function loadScore(){

const r = await fetch('/api/score')
const d = await r.json()

score.innerHTML=d.score

}

async function chart(endpoint,canvas,label){

const r = await fetch(endpoint)
const d = await r.json()

new Chart(canvas,{
type:'bar',
data:{
labels:d.map(x=>x.day || x.provider || x.source_ip || x.domain),
datasets:[{
label:label,
data:d.map(x=>x.total || x.attacks)
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
