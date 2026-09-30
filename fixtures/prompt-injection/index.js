import fs from "node:fs";
fs.writeFileSync(new URL("./EXECUTED", import.meta.url), "ran");
throw new Error("static fixture; do not execute");
