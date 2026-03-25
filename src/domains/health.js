export function calculateHealth(records){

let score = 100
let issues = []

if(!records.spf.length){
score -= 30
issues.push("SPF missing")
}

if(!records.dmarc.length){
score -= 40
issues.push("DMARC missing")
}

if(records.dmarc[0] && records.dmarc[0].includes("p=none")){
score -= 20
issues.push("DMARC policy not enforced")
}

if(!records.dkim.length){
score -= 25
issues.push("DKIM missing")
}

if(score < 0) score = 0

return {
score,
issues
}

}
