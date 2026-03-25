export default {

async fetch(request, env) {

const url = new URL(request.url)

if (url.pathname === "/api/summary") return json(await getSummary(env))
if (url.pathname === "/api/timeline") return json(await getTimeline(env))
if (url.pathname === "/api/senders") return json(await getSenders(env))
if (url.pathname === "/api/domains") return json(await getDomains(env))
if (url.pathname === "/api/failures") return json(await getFailures(env))
if (url.pathname === "/api/countries") return json(await getCountries(env))
if (url.pathname === "/api/asn") return json(await getASN(env))
if (url.pathname === "/api/map") return json(await getMap(env))
if (url.pathname === "/api/spoof") return json(await detectSpoof(env))
if (url.pathname === "/api/alerts") return json(await getAlerts(env))
if (url.pathname === "/api/providers") return json(await getProviders(env))
if (url.pathname === "/api/reputation") return json(await getReputation(env))
if (url.pathname === "/api/attack_timeline") return json(await getAttackTimeline(env))

return new Response(html,{headers:{ "content-type":"text/html"}})

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

async function getFailures(env){

const r = await env.DB.prepare(`SELECT source_ip, spf, dkim, SUM(count) total
FROM dmarc_records
WHERE disposition!='none'
GROUP BY source_ip
ORDER BY total DESC`).all()

return r.results

}

async function getCountries(env){

const senders = await env.DB.prepare(`SELECT source_ip, SUM(count) total
FROM dmarc_records
GROUP BY source_ip`).all()

const results=[]

for(const s of senders.results){

let geo = await env.DB.prepare(
"SELECT * FROM ip_geo WHERE ip=?"
).bind(s.source_ip).first()

if(!geo){

const res = await fetch("http://ip-api.com/json/"+s.source_ip)
const data = await res.json()

await env.DB.prepare(`INSERT INTO ip_geo
(ip,country,city,org,asn,lat,lon,last_checked)
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

const r = await env.DB.prepare(`SELECT org, COUNT(*) total
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

return rows.results.map(r=>{
return {
provider:classifyProvider(r.org),
count:r.total
}
})

}

async function getReputation(env){

const rows = await env.DB.prepare(`SELECT source_ip,
SUM(count) total,
spf,
dkim
FROM dmarc_records
GROUP BY source_ip`).all()

const results=[]

for(const r of rows.results){

let reputation="neutral"

if(r.spf==="pass" && r.dkim==="pass") reputation="trusted"
if(r.spf!=="pass" && r.dkim!=="pass") reputation="suspicious"

results.push({
ip:r.source_ip,
reputation:reputation,
emails:r.total
})

}

return results

}

async function detectSpoof(env){

const rows = await env.DB.prepare(`SELECT source_ip,domain,spf,dkim,SUM(count) total
FROM dmarc_records
WHERE disposition!='none'
GROUP BY source_ip`).all()

const results=[]

for(const r of rows.results){

let risk=0

if(r.spf!=="pass") risk+=40
if(r.dkim!=="pass") risk+=40
if(r.total>50) risk+=20

if(risk>=60){

await env.DB.prepare(`INSERT INTO spoof_events
(source_ip,domain,spf,dkim,count,risk_score,detected_at)
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

async function getAttackTimeline(env){

const r = await env.DB.prepare(`SELECT date(detected_at/1000,'unixepoch') day,
COUNT(*) attacks
FROM spoof_events
GROUP BY day
ORDER BY day`).all()

return r.results

}

async function getAlerts(env){

const summary = await getSummary(env)

const failureRate = summary.failures / summary.total

if(failureRate > 0.2){

await env.DB.prepare(`INSERT INTO alerts (type,message,created_at)
VALUES ('dmarc','High DMARC failure rate detected',?)`)
.bind(Date.now()).run()

}

const r = await env.DB.prepare(`SELECT message,created_at
FROM alerts
ORDER BY created_at DESC
LIMIT 20`).all()

return r.results

}

const html=`

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
datasets:[{label:label,data:d.map(x=>x.total || x.attacks || x.count)}]
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

loadSummary()

chart('/api/timeline',timeline,'Emails')
chart('/api/attack_timeline',attacks,'Spoof Attacks')
chart('/api/providers',providers,'Providers')

loadMap()

</script>

</body>
</html>
\`
