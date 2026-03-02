/**
 * Security Module — Pattern Matching Tests
 *
 * Tests for parseBashPattern, globToRegex, and matchesAnyPattern.
 */

import { strict as assert } from "node:assert";

let passed = 0;
let failed = 0;
const results: { name: string; status: "PASS" | "FAIL"; error?: string }[] = [];

async function test(name: string, fn: () => void | Promise<void>) {
  try {
    await fn();
    passed++;
    results.push({ name, status: "PASS" });
    console.log(`  ✓ ${name}`);
  } catch (err: any) {
    failed++;
    results.push({ name, status: "FAIL", error: err.message });
    console.log(`  ✗ ${name}`);
    console.log(`    ${err.message}`);
  }
}

import {
  parseBashPattern,
  globToRegex,
  matchesAnyPattern,
} from "../build/security.js";

async function main() {
  console.log("\nSecurity Module — Pattern Matching Tests");
  console.log("========================================\n");

  // ── parseBashPattern ──

  await test("parseBashPattern: extracts glob from Bash(glob)", () => {
    assert.equal(parseBashPattern("Bash(sudo *)"), "sudo *");
  });

  await test("parseBashPattern: handles colon format", () => {
    assert.equal(parseBashPattern("Bash(tree:*)"), "tree:*");
  });

  await test("parseBashPattern: returns null for non-Bash", () => {
    assert.equal(parseBashPattern("Read(.env)"), null);
  });

  await test("parseBashPattern: returns null for malformed", () => {
    assert.equal(parseBashPattern("Bash("), null);
    assert.equal(parseBashPattern("notapattern"), null);
  });

  // ── globToRegex: word boundary tests from SECURITY.md ──

  await test("glob: 'ls *' matches 'ls -la'", () => {
    assert.ok(globToRegex("ls *").test("ls -la"));
  });

  await test("glob: 'ls *' does NOT match 'lsof -i'", () => {
    assert.ok(!globToRegex("ls *").test("lsof -i"));
  });

  await test("glob: 'ls*' matches 'lsof -i' (prefix)", () => {
    assert.ok(globToRegex("ls*").test("lsof -i"));
  });

  await test("glob: 'ls*' matches 'ls -la'", () => {
    assert.ok(globToRegex("ls*").test("ls -la"));
  });

  await test("glob: 'git *' matches 'git commit -m msg'", () => {
    assert.ok(globToRegex("git *").test('git commit -m "msg"'));
  });

  await test("glob: '* commit *' matches 'git commit -m msg'", () => {
    assert.ok(globToRegex("* commit *").test('git commit -m "msg"'));
  });

  // ── globToRegex: colon separator ──

  await test("glob: 'tree:*' matches 'tree' (no args)", () => {
    assert.ok(globToRegex("tree:*").test("tree"));
  });

  await test("glob: 'tree:*' matches 'tree -a'", () => {
    assert.ok(globToRegex("tree:*").test("tree -a"));
  });

  await test("glob: 'tree:*' does NOT match 'treemap'", () => {
    assert.ok(!globToRegex("tree:*").test("treemap"));
  });

  // ── globToRegex: real-world deny patterns ──

  await test("glob: 'sudo *' matches 'sudo apt install'", () => {
    assert.ok(globToRegex("sudo *").test("sudo apt install"));
  });

  await test("glob: 'sudo *' does NOT match 'sudoedit'", () => {
    assert.ok(!globToRegex("sudo *").test("sudoedit"));
  });

  await test("glob: 'rm -rf /*' matches 'rm -rf /etc'", () => {
    assert.ok(globToRegex("rm -rf /*").test("rm -rf /etc"));
  });

  await test("glob: 'chmod -R 777 *' matches 'chmod -R 777 /tmp'", () => {
    assert.ok(globToRegex("chmod -R 777 *").test("chmod -R 777 /tmp"));
  });

  // ── globToRegex: case sensitivity ──

  await test("glob: case-insensitive 'dir *' matches 'DIR /W'", () => {
    assert.ok(globToRegex("dir *", true).test("DIR /W"));
  });

  await test("glob: case-sensitive 'dir *' does NOT match 'DIR /W'", () => {
    assert.ok(!globToRegex("dir *", false).test("DIR /W"));
  });

  // ── matchesAnyPattern ──

  await test("matchesAnyPattern: returns matching pattern on hit", () => {
    const result = matchesAnyPattern(
      "sudo apt install",
      ["Bash(git:*)", "Bash(sudo *)"],
      false,
    );
    assert.equal(result, "Bash(sudo *)");
  });

  await test("matchesAnyPattern: returns null on miss", () => {
    const result = matchesAnyPattern(
      "npm install",
      ["Bash(sudo *)", "Bash(rm -rf /*)"],
      false,
    );
    assert.equal(result, null);
  });

  // ── Summary ──
  console.log(`\n${"=".repeat(50)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log("=".repeat(50));
  if (failed > 0) {
    for (const r of results.filter((r) => r.status === "FAIL")) {
      console.log(`  ✗ ${r.name}: ${r.error}`);
    }
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
