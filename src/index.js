export default {

async fetch(request, env) {

const url = new URL(request.url)

if (url.pathname === "/api/summary") {

const data = await env.DB.prepare(`

SELECT
SUM(count) as total,
SUM(CASE WHEN spf='pass' THEN count ELSE 0 END) as spf_pass,
SUM(CASE WHEN dkim='pass' THEN count ELSE 0 END) as dkim_pass,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) as failures
FROM dmarc_records

`).first()

return Response.json(data)

}

if (url.pathname === "/api/senders") {

const data = await env.DB.prepare(`

SELECT source_ip, SUM(count) as total
FROM dmarc_records
GROUP BY source_ip
ORDER BY total DESC
LIMIT 10

`).all()

return Response.json(data.results)

}

if (url.pathname === "/api/timeline") {

const data = await env.DB.prepare(`

SELECT
date(created_at/1000,'unixepoch') as day,
SUM(count) as total
FROM dmarc_records
GROUP BY day
ORDER BY day

`).all()

return Response.json(data.results)

}

if (url.pathname === "/api/domains") {

const data = await env.DB.prepare(`

SELECT domain, SUM(count) as total
FROM dmarc_records
GROUP BY domain
ORDER BY total DESC

`).all()

return Response.json(data.results)

}

if (url.pathname === "/api/failures") {

const data = await env.DB.prepare(`

SELECT source_ip, spf, dkim, SUM(count) as total
FROM dmarc_records
WHERE disposition!='none'
GROUP BY source_ip
ORDER BY total DESC

`).all()

return Response.json(data.results)

}

return new Response(html, {
headers: { "content-type": "text/html" }
})

}

}

const html = `

<html>

<head>

<title>DMARC Security Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

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

<h1>DMARC Security Dashboard</h1>

<div class="grid">

<div class="card">
<h3>Total Emails</h3>
<div id="total"></div>
</div>

<div class="card">
<h3>SPF Pass</h3>
<div id="spf"></div>
</div>

<div class="card">
<h3>DKIM Pass</h3>
<div id="dkim"></div>
</div>

<div class="card">
<h3>Failures</h3>
<div id="failures"></div>
</div>

</div>

<div class="card">
<h3>Email Volume Timeline</h3>
<canvas id="timeline"></canvas>
</div>

<br>

<div class="card">
<h3>Top Sending IPs</h3>
<canvas id="senders"></canvas>
</div>

<br>

<div class="card">
<h3>Sending Domains</h3>
<canvas id="domains"></canvas>
</div>

<br>

<div class="card">
<h3>Authentication Failures</h3>
<table id="failTable"></table>
</div>

<script>

async function loadSummary(){

const r = await fetch('/api/summary')
const d = await r.json()

document.getElementById('total').innerHTML = d.total
document.getElementById('spf').innerHTML = d.spf_pass
document.getElementById('dkim').innerHTML = d.dkim_pass
document.getElementById('failures').innerHTML = d.failures

}

async function loadTimeline(){

const r = await fetch('/api/timeline')
const d = await r.json()

new Chart(document.getElementById('timeline'),{

type:'line',

data:{
labels:d.map(x=>x.day),
datasets:[{
label:'Emails',
data:d.map(x=>x.total)
}]
}

})

}

async function loadSenders(){

const r = await fetch('/api/senders')
const d = await r.json()

new Chart(document.getElementById('senders'),{

type:'bar',

data:{
labels:d.map(x=>x.source_ip),
datasets:[{
label:'Emails',
data:d.map(x=>x.total)
}]
}

})

}

async function loadDomains(){

const r = await fetch('/api/domains')
const d = await r.json()

new Chart(document.getElementById('domains'),{

type:'pie',

data:{
labels:d.map(x=>x.domain),
datasets:[{
data:d.map(x=>x.total)
}]
}

})

}

async function loadFailures(){

const r = await fetch('/api/failures')
const d = await r.json()

let html="<tr><th>IP</th><th>SPF</th><th>DKIM</th><th>Count</th></tr>"

d.forEach(x=>{
html += "<tr>"
html += "<td>"+x.source_ip+"</td>"
html += "<td>"+x.spf+"</td>"
html += "<td>"+x.dkim+"</td>"
html += "<td>"+x.total+"</td>"
html += "</tr>"
})

document.getElementById("failTable").innerHTML = html

}

loadSummary()
loadTimeline()
loadSenders()
loadDomains()
loadFailures()

</script>

</body>

</html>

`
