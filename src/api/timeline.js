
export async function getTimeline(env){

const r = await env.DB.prepare(`
SELECT date(created_at/1000,'unixepoch') day,
SUM(count) total
FROM dmarc_records
GROUP BY day
ORDER BY day
`).all()

return r.results

}
