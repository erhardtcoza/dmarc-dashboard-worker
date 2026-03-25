
export async function getIPDetails(env,ip){

const r = await env.DB.prepare(`
SELECT domain,
SUM(count) total,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records
WHERE source_ip=?
GROUP BY domain
`).bind(ip).all()

return r.results

}

export async function getDomainDetails(env,domain){

const r = await env.DB.prepare(`
SELECT source_ip,
SUM(count) total,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records
WHERE domain=?
GROUP BY source_ip
`).bind(domain).all()

return r.results

}

export async function getDayDetails(env,day){

const r = await env.DB.prepare(`
SELECT source_ip,domain,
SUM(count) total,
SUM(CASE WHEN disposition!='none' THEN count ELSE 0 END) failures
FROM dmarc_records
WHERE date(created_at/1000,'unixepoch')=?
GROUP BY source_ip,domain
`).bind(day).all()

return r.results

}
