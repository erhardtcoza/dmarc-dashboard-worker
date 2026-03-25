export default {
  async fetch(request, env) {

    const url = new URL(request.url)

    if (url.pathname === "/api/summary") {

      const result = await env.DB.prepare(`
        SELECT
          SUM(count) as total,
          SUM(CASE WHEN spf='pass' THEN count ELSE 0 END) as spf_pass,
          SUM(CASE WHEN dkim='pass' THEN count ELSE 0 END) as dkim_pass,
          SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) as failures
        FROM dmarc_records
      `).first()

      return Response.json(result)
    }

    if (url.pathname === "/api/senders") {

      const result = await env.DB.prepare(`
        SELECT source_ip, SUM(count) as total
        FROM dmarc_records
        GROUP BY source_ip
        ORDER BY total DESC
        LIMIT 10
      `).all()

      return Response.json(result.results)
    }

    if (url.pathname === "/api/domains") {

      const result = await env.DB.prepare(`
        SELECT domain, SUM(count) as total
        FROM dmarc_records
        GROUP BY domain
        ORDER BY total DESC
      `).all()

      return Response.json(result.results)
    }

    if (url.pathname === "/api/failures") {

      const result = await env.DB.prepare(`
        SELECT source_ip, spf, dkim, SUM(count) as total
        FROM dmarc_records
        WHERE disposition!='none'
        GROUP BY source_ip
        ORDER BY total DESC
      `).all()

      return Response.json(result.results)
    }

    return new Response(dashboardHTML, {
      headers: { "content-type": "text/html" }
    })
  }
}

const dashboardHTML = `

<html>

<head>

<title>DMARC Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

body{
font-family:Arial;
background:#111;
color:white;
padding:40px;
}

.card{
background:#1e1e1e;
padding:20px;
margin-bottom:20px;
border-radius:10px;
}

canvas{
background:white;
border-radius:10px;
padding:10px;
}

</style>

</head>

<body>

<h1>DMARC Monitoring</h1>

<div class="card">
<h3>Overview</h3>
<div id="summary"></div>
</div>

<div class="card">
<h3>Top Sending IPs</h3>
<canvas id="sendersChart"></canvas>
</div>

<div class="card">
<h3>Domains</h3>
<canvas id="domainChart"></canvas>
</div>

<div class="card">
<h3>Failures</h3>
<table id="failures"></table>
</div>

<script>

async function loadSummary(){

const res = await fetch('/api/summary')
const data = await res.json()

document.getElementById("summary").innerHTML =
"Total Emails: " + data.total +
"<br>SPF Pass: " + data.spf_pass +
"<br>DKIM Pass: " + data.dkim_pass +
"<br>Failures: " + data.failures

}

async function loadSenders(){

const res = await fetch('/api/senders')
const data = await res.json()

new Chart(document.getElementById('sendersChart'),{
type:'bar',
data:{
labels:data.map(x=>x.source_ip),
datasets:[{
label:'Emails',
data:data.map(x=>x.total)
}]
}
})

}

async function loadDomains(){

const res = await fetch('/api/domains')
const data = await res.json()

new Chart(document.getElementById('domainChart'),{
type:'pie',
data:{
labels:data.map(x=>x.domain),
datasets:[{
data:data.map(x=>x.total)
}]
}
})

}

async function loadFailures(){

const res = await fetch('/api/failures')
const data = await res.json()

let html = "<tr><th>IP</th><th>SPF</th><th>DKIM</th><th>Count</th></tr>"

data.forEach(row=>{
html += "<tr>"
html += "<td>"+row.source_ip+"</td>"
html += "<td>"+row.spf+"</td>"
html += "<td>"+row.dkim+"</td>"
html += "<td>"+row.total+"</td>"
html += "</tr>"
})

document.getElementById("failures").innerHTML = html

}

loadSummary()
loadSenders()
loadDomains()
loadFailures()

</script>

</body>
</html>

`
