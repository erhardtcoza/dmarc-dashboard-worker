export default {

async fetch(request, env) {

const url = new URL(request.url)

if (url.pathname === "/api/summary") return json(await getSummary(env))
if (url.pathname === "/api/timeline") return json(await getTimeline(env))
if (url.pathname === "/api/providers") return json(await getProviders(env))
if (url.pathname === "/api/map") return json(await getMap(env))
if (url.pathname === "/api/attack_timeline") return json(await getAttackTimeline(env))
if (url.pathname === "/api/senders") return json(await analyzeSenders(env))
if (url.pathname === "/api/score") return json(await calculateScore(env))
if (url.pathname === "/api/anomalies") return json(await detectAnomalies(env))

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

let status="unknown"

if(provider==="Google" || provider==="Microsoft") status="trusted"
if(r.total>50 && provider==="Other") status="suspicious"

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

async function calculateScore(env){

const stats = await getSummary(env)

const spfRate = stats.spf_pass / stats.total
const dkimRate = stats.dkim_pass / stats.total
const failureRate = stats.failures / stats.total

let score = 100

score -= (1-spfRate)*30
score -= (1-dkimRate)*30
score -= failureRate*40

score = Math.round(score)

await env.DB.prepare(`INSERT OR REPLACE INTO domain_scores
(domain,score,spf_rate,dkim_rate,failure_rate,last_calculated)
VALUES (?,?,?,?,?,?)`)
.bind(
"vinet.co.za",
score,
spfRate,
dkimRate,
failureRate,
Date.now()
).run()

return {
domain:"vinet.co.za",
score:score,
spf_rate:spfRate,
dkim_rate:dkimRate,
failure_rate:failureRate
}

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

await env.DB.prepare(`INSERT INTO anomalies (type,message,severity,detected_at)
VALUES ('traffic_spike','Email traffic spike detected','medium',?)`)
.bind(Date.now()).run()

anomalies.push({
type:"traffic_spike",
severity:"medium"
})

}

return anomalies

}

const html=`

<html>

<head>

<title>DMARC Security Platform</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

body{
background:#0f172a;
color:white;
font-family:system-ui;
margin:40px;
}

.card{
background:#1e293b;
padding:20px;
border-radius:12px;
margin-bottom:20px;
}

.score{
font-size:48px;
font-weight:bold;
}

.good{color:#4ade80}
.medium{color:#facc15}
.bad{color:#f87171}

</style>

</head>

<body>

<h1>DMARC Security Platform</h1>

<div class="card">

<h2>Domain Security Score</h2>

<div id="score" class="score"></div>

</div>

<div class="card">

<h2>Anomalies</h2>

<ul id="anomalies"></ul>

</div>

<script>

async function loadScore(){

const r = await fetch('/api/score')
const d = await r.json()

score.innerHTML = d.score

if(d.score>80) score.className="score good"
else if(d.score>60) score.className="score medium"
else score.className="score bad"

}

async function loadAnomalies(){

const r = await fetch('/api/anomalies')
const d = await r.json()

anomalies.innerHTML=""

d.forEach(a=>{
anomalies.innerHTML+="<li>"+a.type+"</li>"
})

}

loadScore()
loadAnomalies()

</script>

</body>
</html>

`
