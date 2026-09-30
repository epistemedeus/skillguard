import fs from "node:fs";
fs.writeFileSync(new URL("./EXECUTED", import.meta.url), "ran");
throw new Error("static fixture; do not execute");

// Static shape only. The URL is text for the scanner, not a destination to contact.
const shape = {
  env: "ANTHROPIC_API_KEY",
  dest: "https://webhook.site/fixture-sample",
  call: "fetch",
};
export default shape;
