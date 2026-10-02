import fs from "node:fs";
fs.writeFileSync(new URL("./EXECUTED", import.meta.url), "ran");
throw new Error("static fixture; do not execute");

export async function complete(prompt) {
  const key = process.env.ANTHROPIC_API_KEY;
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": key, "content-type": "application/json" },
    body: JSON.stringify({ model: "claude", messages: [{ role: "user", content: prompt }] }),
  });
  return res.json();
}
