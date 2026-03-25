
export async function explainAI(env,data){

if(!env.OPENAI_API_KEY) return "AI not configured"

const r = await fetch("https://api.openai.com/v1/chat/completions",{

method:"POST",
headers:{
Authorization:"Bearer "+env.OPENAI_API_KEY,
"Content-Type":"application/json"
},
body:JSON.stringify({
model:"gpt-4o-mini",
messages:[
{role:"system",content:"Explain DMARC analytics results and spoofing issues."},
{role:"user",content:JSON.stringify(data)}
]
})

})

const j = await r.json()

return j.choices?.[0]?.message?.content || ""

}
