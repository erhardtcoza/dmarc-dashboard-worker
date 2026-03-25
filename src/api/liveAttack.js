
export async function getLiveAttack(env){

const r = await env.DB.prepare(`
SELECT source_ip,SUM(count) failures
FROM dmarc_records
WHERE disposition!='none'
GROUP BY source_ip
ORDER BY failures DESC
LIMIT 1
`).first()

return r||{}

}
