
export async function getSenders(env){

const r = await env.DB.prepare(`
SELECT source_ip,SUM(count) total
FROM dmarc_records
GROUP BY source_ip
ORDER BY total DESC
LIMIT 10
`).all()

return r.results

}
