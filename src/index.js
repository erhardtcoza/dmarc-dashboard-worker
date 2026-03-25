export default {

async fetch(request, env) {

const url = new URL(request.url)

if (url.pathname === "/api/summary") return json(await getSummary(env))
if (url.pathname === "/api/timeline") return json(await getTimeline(env))
if (url.pathname === "/api/providers") return json(await getProviders(env))
if (url.pathname === "/api/map") return json(await getMap(env))
if (url.pathname === "/api/attack_timeline") return json(await getAttackTimeline(env))
if (url.pathname === "/api/senders") return json(await analyzeSenders(env))

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

async function analyzeSenders(env){

const rows = await env.DB.prepare(`SELECT source_ip, SUM(count) total
FROM dmarc_records
GROUP BY source_ip`).all()

const results=[]

for(const r of rows.results){

let geo = await env.DB.prepare(
"SELECT * FROM ip_geo WHERE ip=?"
).bind(r.source_ip).first()

if(!geo) continue

const provider = classifyProvider(geo.org)

const trusted = await env.DB.prepare(
"SELECT * FROM trusted_providers WHERE provider=?"
).bind(provider).first()

let status="unknown"

if(trusted) status="trusted"
if(!trusted && r.total>50) status="suspicious"

await env.DB.prepare(`INSERT OR REPLACE INTO sender_activity
(ip,provider,first_seen,last_seen,status)
VALUES (?,?,?,?,?)`)
.bind(
r.source_ip,
provider,
Date.now(),
Date.now(),
status
).run()

results.push({
ip:r.source_ip,
provider:provider,
status:status,
emails:r.total
})

}

return results

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

.trusted{color:#4ade80}
.unknown{color:#facc15}
.suspicious{color:#f87171}

</style>

</head>

<body>

<h1>DMARC Security Platform</h1>

<div class="grid">

<div class="card"><h3>Total</h3><div id="total"></div></div>
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
<h3>Spoof Attack Timeline</h3>
<canvas id="attacks"></canvas>
</div>

<br>

<div class="card">
<h3>Sender Providers</h3>
<canvas id="providers"></canvas>
</div>

<br>

<div class="card">
<h3>Global Sources</h3>
<div id="map"></div>
</div>

<br>

<div class="card">
<h3>Sender Reputation</h3>
<table id="senders"></table>
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

async function chart(endpoint,canvas,label){

const r=await fetch(endpoint)
const d=await r.json()

new Chart(canvas,{
type:'bar',
data:{
labels:d.map(x=>x.day || x.provider),
datasets:[{label:label,data:d.map(x=>x.total || x.attacks)}]
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

async function loadSenders(){

const r=await fetch('/api/senders')
const d=await r.json()

let html="<tr><th>IP</th><th>Provider</th><th>Status</th><th>Emails</th></tr>"

d.forEach(s=>{
html+="<tr>"
html+="<td>"+s.ip+"</td>"
html+="<td>"+s.provider+"</td>"
html+="<td class='"+s.status+"'>"+s.status+"</td>"
html+="<td>"+s.emails+"</td>"
html+="</tr>"
})

senders.innerHTML=html

}

loadSummary()

chart('/api/timeline',timeline,'Emails')
chart('/api/attack_timeline',attacks,'Spoof Attacks')
chart('/api/providers',providers,'Providers')

loadMap()
loadSenders()

</script>

</body>
</html>

`
