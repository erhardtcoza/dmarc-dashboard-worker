export default {

async fetch(request, env) {

const url = new URL(request.url)

if (url.pathname === "/api/domain_lookup") {
const domain = url.searchParams.get("domain")
return json(await lookupDomain(env,domain))
}

if (url.pathname === "/api/bulk_lookup") {
const domains = url.searchParams.get("domains").split(",")
return json(await bulkLookup(env,domains))
}

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

async function aiAdvice(env,data){

if(!env.OPENAI_API_KEY) return "AI advice unavailable"

const r = await fetch("https://api.openai.com/v1/chat/completions",{

method:"POST",

headers:{
"Authorization":"Bearer "+env.OPENAI_API_KEY,
"Content-Type":"application/json"
},

body:JSON.stringify({

model:"gpt-4o-mini",

messages:[
{
role:"system",
content:"You are an email security expert. Analyze SPF, DKIM, DMARC, MX and BIMI records and recommend improvements."
},
{
role:"user",
content:JSON.stringify(data)
}
]

})

})

const j = await r.json()

return j.choices?.[0]?.message?.content || "No advice generated"

}

async function lookupDomain(env,domain){

if(!domain) return {}

const spf = await dnsQuery(domain,"TXT")
const dmarc = await dnsQuery("_dmarc."+domain,"TXT")
const mx = await dnsQuery(domain,"MX")
const bimi = await dnsQuery("default._bimi."+domain,"TXT")

let spfStatus="missing"
let dmarcStatus="missing"
let dkimStatus="missing"
let mxStatus="missing"
let bimiStatus="missing"

spf.forEach(r=>{
if(r.data.includes("v=spf1")) spfStatus="valid"
})

dmarc.forEach(r=>{
if(r.data.includes("p=reject")) dmarcStatus="reject"
else if(r.data.includes("p=quarantine")) dmarcStatus="quarantine"
else dmarcStatus="none"
})

if(mx.length>0) mxStatus="valid"
if(bimi.length>0) bimiStatus="detected"

const selectors=["selector1","selector2","default","google","k1","mail"]

for(const s of selectors){

const res=await dnsQuery(s+"._domainkey."+domain,"TXT")

if(res.length>0){
dkimStatus="detected"
break
}

}

let issues=[]

if(spfStatus==="missing") issues.push("SPF record missing")
if(dmarcStatus==="none") issues.push("DMARC policy not enforced")
if(dkimStatus==="missing") issues.push("DKIM not detected")
if(mxStatus==="missing") issues.push("No MX records found")
if(bimiStatus==="missing") issues.push("BIMI not configured")

const ai = await aiAdvice(env,{
domain,
spf:spfStatus,
dkim:dkimStatus,
dmarc:dmarcStatus,
mx:mxStatus,
bimi:bimiStatus
})

return {
domain,
spf:spfStatus,
dkim:dkimStatus,
dmarc:dmarcStatus,
mx:mxStatus,
bimi:bimiStatus,
issues,
ai
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

const html = `

<html>

<head>

<title>Vinet Email Security Dashboard</title>

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

.card{
background:white;
padding:20px;
border-radius:8px;
box-shadow:0 2px 6px rgba(0,0,0,0.08);
margin-bottom:20px;
}

input{
padding:8px;
width:300px;
}

button{
padding:8px 14px;
margin-left:6px;
background:#e30613;
color:white;
border:none;
border-radius:4px;
cursor:pointer;
}

textarea{
width:100%;
height:80px;
margin-top:10px;
}

table{
width:100%;
border-collapse:collapse;
font-size:13px;
margin-top:15px;
}

td,th{
padding:8px;
border-bottom:1px solid #eee;
}

.bad{color:red;font-weight:bold}
.warn{color:orange;font-weight:bold}
.good{color:green;font-weight:bold}

.ai{
background:#f9fafb;
padding:12px;
border-left:4px solid #e30613;
margin-top:10px;
}

</style>

</head>

<body>

<div class="header">

<img src="https://static.vinet.co.za/logo.jpeg" class="logo">

<strong>Vinet Email Security Dashboard</strong>

</div>

<div class="container">

<div class="card">

<h3>Domain Analyzer</h3>

<input id="domainInput" placeholder="example.com">

<button onclick="scanDomain()">Scan</button>

<br><br>

<textarea id="bulkDomains" placeholder="example.com&#10;vinet.co.za"></textarea>

<button onclick="bulkScan()">Bulk Scan</button>

<div id="domainResult"></div>

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

let html="<table><tr><th>Domain</th><th>SPF</th><th>DKIM</th><th>DMARC</th><th>MX</th><th>BIMI</th><th>Issues</th></tr>"

data.forEach(d=>{

html+="<tr>"
html+="<td>"+d.domain+"</td>"
html+="<td>"+d.spf+"</td>"
html+="<td>"+d.dkim+"</td>"
html+="<td>"+d.dmarc+"</td>"
html+="<td>"+d.mx+"</td>"
html+="<td>"+d.bimi+"</td>"
html+="<td>"+d.issues.length+"</td>"
html+="</tr>"

})

html+="</table>"

data.forEach(d=>{

if(d.ai){

html+="<div class='ai'><b>"+d.domain+" AI Advice</b><br>"+d.ai+"</div>"

}

})

domainResult.innerHTML=html

}

</script>

</body>

</html>

`
