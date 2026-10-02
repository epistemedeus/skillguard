// Fixture-secret classifier: S22 sentinel in an s22-fixture directory, plus
// real-secret negatives. A fixture path or a test filename is not an exemption.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { S22_FIXTURE_SECRET, classifySecretText } from "../secrets.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cli = path.join(root, "index.js");
const REAL_SECRET = `sk-ant-${"Real9Key".repeat(4)}`;

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 20000,
  });
}

function writeTree(dir, name, text) {
  const file = path.join(dir, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
}

test("classifier names S22 only for the sentinel inside s22-fixture", () => {
  const sentinel = `const key = "${S22_FIXTURE_SECRET}";\n`;
  const real = `const key = "${REAL_SECRET}";\n`;
  assert.equal(classifySecretText(sentinel, "s22-fixture/sample.js").class, "fixture-secret");
  assert.equal(classifySecretText(sentinel, "s22-fixture/sample.js").id, "S22");
  assert.equal(classifySecretText(sentinel, "src/index.js").class, "real-secret");
  assert.equal(classifySecretText(sentinel, "tests/verifier-client.test.js").class, "real-secret");
  assert.equal(classifySecretText(real, "s22-fixture/sample.js").class, "real-secret");
  assert.equal(classifySecretText(real, "fixtures/harmless/index.js").class, "real-secret");
  assert.equal(classifySecretText(real, "tests/verifier-client.test.js").class, "real-secret");
  assert.equal(classifySecretText(`${sentinel}${real}`, "s22-fixture/sample.js").class, "real-secret");
  assert.equal(classifySecretText("no credential here", "s22-fixture/sample.js").class, "none");
  assert.notEqual(REAL_SECRET, S22_FIXTURE_SECRET);
});

test("S22 sentinel is not secret-literal and a real secret in the same class is", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "skillguard-s22-"));
  try {
    writeTree(dir, "s22-fixture/sample.js", `const key = "${S22_FIXTURE_SECRET}";\n`);
    const fixture = run([dir, "--json"]);
    assert.equal(fixture.status, 0, fixture.stdout + fixture.stderr);
    assert.equal(fixture.stdout.includes("secret-literal"), false);

    writeTree(dir, "s22-fixture/real.js", `const key = "${REAL_SECRET}";\n`);
    const mixed = run([dir, "--json"]);
    assert.equal(mixed.status, 3, mixed.stdout + mixed.stderr);
    assert.match(mixed.stdout, /secret-literal/);
    assert.equal(mixed.stdout.includes(REAL_SECRET), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a real secret in fixtures or a test file is still secret-literal", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "skillguard-real-"));
  try {
    writeTree(dir, "fixtures/harmless/index.js", `const key = "${REAL_SECRET}";\n`);
    const fixtureDir = run([dir, "--json"]);
    assert.equal(fixtureDir.status, 3, fixtureDir.stdout + fixtureDir.stderr);
    assert.match(fixtureDir.stdout, /secret-literal/);

    const tests = fs.mkdtempSync(path.join(os.tmpdir(), "skillguard-testfile-"));
    try {
      writeTree(tests, "verifier-client.test.js", `const key = "${REAL_SECRET}";\n`);
      const testFile = run([tests, "--json"]);
      assert.equal(testFile.status, 3, testFile.stdout + testFile.stderr);
      assert.match(testFile.stdout, /secret-literal/);
      assert.equal(testFile.stdout.includes(REAL_SECRET), false);
    } finally {
      fs.rmSync(tests, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
