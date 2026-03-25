
export async function getReputation(env){

const rows = await env.DB.prepare(`
SELECT source_ip,
SUM(count) total,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records
GROUP BY source_ip
ORDER BY total DESC
LIMIT 10
`).all()

return rows.results.map(r=>{

let status="Neutral"
let reason="Normal traffic"

if(r.failures>100){
status="Malicious"
reason=r.failures+" DMARC failures"
}
else if(r.failures>20){
status="Suspicious"
reason="High failure rate"
}

return{
ip:r.source_ip,
total:r.total,
failures:r.failures,
status,
reason
}

})

}
