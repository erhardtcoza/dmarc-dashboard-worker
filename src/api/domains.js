
export async function getDomains(env){

const r = await env.DB.prepare(`
SELECT domain,SUM(count) total
FROM dmarc_records
GROUP BY domain
ORDER BY total DESC
`).all()

return r.results

}
