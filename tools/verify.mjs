#!/usr/bin/env node
// F2 rung one (VISION.md section 2): the client-side verifier, as a CLI.
//
// Checks that what the ic-git canister serves is what the on-chain
// ProvenanceRegistry attests, from the user's own trust domain:
//
//   A. served /site/<repo>/<path> carries X-Ic-Git-Commit equal to the
//      registry entry's commit (the canister's on-chain attestation);
//   B. sha256 of the artifact equals the registry entry's bundleHash;
//   C. (--contract) the deployed runtime bytecode is a trailing slice of
//      the attested creation bytecode (advisory: constructors that write
//      immutables legitimately transform it);
//   D. (if git is installed) an independent `git clone` of the repo from
//      the canister contains that commit, and the blob at <commit>:<path>
//      is byte-identical to what was served.
//   E. (site records) the served entrypoint's own markup references are
//      enforceable -- a port of the canister's site::unverifiable_subresource.
//      A matching hash on a page that pulls un-integrity'd code is a FAILED
//      verification, never a passed one (docs/ATTESTATION.md, step 1): this
//      record attests ONE blob, so a subresource without SRI is covered by
//      nothing and a hostile gateway can swap it while A-D all pass. Checked
//      here independently because the publish-time guard is not retroactive:
//      records written before it shipped may cover pages that fail it.
//
// Zero dependencies (node >= 18: fetch + crypto). The one piece of
// precomputation is the registry getter's 4-byte selector, because node has
// no keccak256: get(string) -> 0x693ec85e. Recompute it yourself with any
// keccak tool; the registry source is itself cloneable from the canister
// (repo "registry") and attested in the same registry it serves.
//
// The registry stores one entry per key STRING, and the canister writes two
// kinds of record with incompatible bundleHash semantics: a deploy-artifact
// record under "<repo>" (sha256 of decoded contract bytecode) and a served-site
// record under "<repo>#site" (sha256 of the served bytes). --record picks one;
// the default resolves it (see resolveRecord below) so a repo that has only one
// of them just works, and a repo that has both is never checked against the
// wrong one.
//
// Usage:
//   node tools/verify.mjs <repo> <path> [--contract 0x...]
//     [--record auto|site|deploy]
//     [--canister umobs-yiaaa-aaaab-agyrq-cai]
//     [--registry 0xa1362DAda583c56a395D305a8C7A458E0B62A209]
//     [--rpc https://ethereum-sepolia-rpc.publicnode.com]

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const GET_SELECTOR = "693ec85e"; // keccak256("get(string)")[..4]
const SITE_SUFFIX = "#site"; // must match provenance.rs::SITE_KEY_SUFFIX

const args = process.argv.slice(2);
const positional = [];
const opts = {
  canister: "umobs-yiaaa-aaaab-agyrq-cai",
  registry: "0xa1362DAda583c56a395D305a8C7A458E0B62A209",
  rpc: "https://ethereum-sepolia-rpc.publicnode.com",
  contract: null,
  record: "auto",
};
for (let i = 0; i < args.length; i++) {
  if (args[i].startsWith("--")) {
    opts[args[i].slice(2)] = args[++i];
  } else {
    positional.push(args[i]);
  }
}
const [repo, path] = positional;
if (!repo || !path) {
  console.error("usage: verify.mjs <repo> <path> [--contract 0x...] [--record auto|site|deploy] [--canister id] [--registry 0x...] [--rpc url]");
  process.exit(2);
}
if (!["auto", "site", "deploy"].includes(opts.record)) {
  console.error(`--record must be auto, site, or deploy (got "${opts.record}")`);
  process.exit(2);
}
const gateway = `https://${opts.canister}.raw.icp0.io`;

let failures = 0;
const report = (ok, label, detail) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` -- ${detail}` : ""}`);
  if (!ok) failures++;
};
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

// --- entrypoint reference scan (check E) -------------------------------------
// Port of canisters/git/src/site.rs::unverifiable_subresource; the two must
// track each other. Returns a reason string when the entrypoint names a
// subresource the browser will not enforce, else null. Same bias as the
// canister: every ambiguity refuses, because a false refusal costs one edit
// and a false accept reports "verified" over swappable code.

const isWs = (c) => " \t\n\r\f".includes(c); // Rust is_ascii_whitespace

// True when an integrity value holds at least one token the SRI spec
// recognizes (sha256/384/512 + base64, options after `?`). The spec makes the
// browser IGNORE metadata that parses to an empty set -- the resource then
// loads with no check at all -- so presence alone proves nothing.
const integrityEnforceable = (value) =>
  value.split(/[ \t\n\r\f]+/).some((tok) => {
    const m = /^sha(?:256|384|512)-([^?]*)/.exec(tok);
    return m !== null && m[1].length > 0 && /^[a-zA-Z0-9+/=]+$/.test(m[1]);
  });

function unverifiableSubresource(servedPath, body) {
  // Gate on the served file's NAME, case-insensitively; an extensionless
  // blob could be a page, so it is scanned rather than skipped.
  const name = servedPath.split("/").pop();
  const dot = name.lastIndexOf(".");
  const markup =
    dot === -1 || ["html", "htm", "xhtml", "svg"].includes(name.slice(dot + 1).toLowerCase());
  if (!markup) return null;
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    return "entrypoint is not valid UTF-8, so its references cannot be read";
  }
  // ASCII-only lowercasing, mirroring the canister's to_ascii_lowercase.
  const hay = text.replace(/[A-Z]/g, (c) => c.toLowerCase());

  // Tokenize one tag's attributes the way the browser does: a new attribute
  // may begin after whitespace, `/`, or a closing quote; quotes delimit a
  // value only immediately after `=`; an unquoted value ends at whitespace
  // or `>`. Returns {attrs, end} or null when the tag never closes.
  const parseTag = (from) => {
    const attrs = [];
    let i = from;
    for (;;) {
      while (i < hay.length && (isWs(hay[i]) || hay[i] === "/")) i++;
      if (i >= hay.length) return null;
      if (hay[i] === ">") return { attrs, end: i };
      const nameStart = i;
      while (i < hay.length && !isWs(hay[i]) && !"/=>".includes(hay[i])) i++;
      const attrName = hay.slice(nameStart, i);
      let j = i;
      while (j < hay.length && isWs(hay[j])) j++;
      if (j < hay.length && hay[j] === "=") {
        j++;
        while (j < hay.length && isWs(hay[j])) j++;
        if (j >= hay.length) return null;
        let value;
        if (hay[j] === '"' || hay[j] === "'") {
          const ve = hay.indexOf(hay[j], j + 1);
          if (ve === -1) return null;
          value = hay.slice(j + 1, ve);
          j = ve + 1;
        } else {
          const vs = j;
          while (j < hay.length && !isWs(hay[j]) && hay[j] !== ">") j++;
          value = hay.slice(vs, j);
        }
        attrs.push([attrName, value]);
        i = j;
      } else {
        attrs.push([attrName, ""]);
      }
    }
  };

  let i = 0;
  for (;;) {
    const lt = hay.indexOf("<", i);
    if (lt === -1 || lt + 1 >= hay.length) return null;
    const c = hay[lt + 1];
    if (!/[a-z]/.test(c)) {
      // Closing tag, comment, doctype, or bogus comment: nothing inside one
      // executes before its first `>`, so skip there; a stray `<` is text.
      if (c === "/" || c === "!" || c === "?") {
        const gt = hay.indexOf(">", lt + 1);
        if (gt === -1) return null;
        i = gt + 1;
      } else {
        i = lt + 1;
      }
      continue;
    }
    let nameEnd = lt + 1;
    while (nameEnd < hay.length && /[a-z0-9]/.test(hay[nameEnd])) nameEnd++;
    const tag = hay.slice(lt + 1, nameEnd);
    const parsed = parseTag(nameEnd);
    if (parsed === null) return `<${tag}> tag is never closed`;
    i = parsed.end + 1;
    // First occurrence wins, as in the browser.
    const get = (n) => parsed.attrs.find(([an]) => an === n)?.[1];
    // The browser decodes character references in values; this scanner does
    // not, so a keyword value hiding one is refused, not compared wrong.
    const charRef = (an, v) =>
      v.includes("&")
        ? `<${tag} ${an}=...> value holds a character reference this scanner does not decode`
        : null;
    if (tag === "iframe" || tag === "object" || tag === "embed") {
      return `<${tag}> loads content SRI cannot cover; inline the content instead`;
    }
    if (tag === "base" && get("href") !== undefined) {
      return "<base href=...> relocates every relative URL on the page";
    }
    if (tag === "meta") {
      const v = get("http-equiv");
      if (v !== undefined) {
        const bad = charRef("http-equiv", v);
        if (bad) return bad;
        if (v.trim() === "refresh") {
          return "<meta http-equiv=refresh> navigates away from the attested page";
        }
      }
    }
    if (tag === "script") {
      if (get("href") !== undefined || get("xlink:href") !== undefined) {
        return "<script href=...> (SVG form) loads a subresource SRI cannot cover";
      }
      if (get("src") !== undefined) {
        const integ = get("integrity");
        if (integ === undefined || !integrityEnforceable(integ)) {
          return "<script src=...> has no enforceable integrity=";
        }
      } else {
        const t = get("type");
        if (t !== undefined) {
          const bad = charRef("type", t);
          if (bad) return bad;
          if (t.trim() === "module") {
            return "inline <script type=module> imports files SRI cannot cover";
          }
        }
      }
    }
    if (tag === "link") {
      const rel = get("rel") ?? "";
      const bad = charRef("rel", rel);
      if (bad) return bad;
      const enforced = rel
        .split(/[ \t\n\r\f]+/)
        .some((r) => r === "stylesheet" || r === "modulepreload");
      const integ = get("integrity");
      if (
        enforced &&
        get("href") !== undefined &&
        (integ === undefined || !integrityEnforceable(integ))
      ) {
        return `<link rel="${rel}"> has no enforceable integrity=`;
      }
    }
  }
}

// ABI-encode get(string repo): selector, offset word, length word, padded data.
function encodeGet(repo) {
  const utf8 = Buffer.from(repo, "utf8");
  const pad = Buffer.alloc((32 - (utf8.length % 32)) % 32);
  const word = (n) => Buffer.from(n.toString(16).padStart(64, "0"), "hex");
  return (
    "0x" +
    GET_SELECTOR +
    Buffer.concat([word(0x20), word(utf8.length), utf8, pad]).toString("hex")
  );
}

async function rpc(method, params) {
  const res = await fetch(opts.rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

// Decode get(string) -> (bytes20 commit, bytes32 bundleHash, uint64 updatedAt).
// An unwritten key returns three zero words rather than reverting, so an
// all-zero commit is the "no such record" signal.
function decodeGet(callRet) {
  const ret = callRet.slice(2);
  return {
    commit: ret.slice(0, 40), // bytes20, left-aligned in word 0
    bundleHash: ret.slice(64, 128), // bytes32, word 1
    updatedAt: parseInt(ret.slice(128, 192), 16), // uint64, word 2
    present: !/^0*$/.test(ret.slice(0, 40)),
  };
}

// --- gather ------------------------------------------------------------------

// The two record keys, named once: the key that is read and the key that is
// reported must not be able to drift apart.
const keys = { site: repo + SITE_SUFFIX, deploy: repo };

// Both registry records and the served artifact are independent reads; fetch
// them concurrently. Reading both keys costs one extra eth_call and no extra
// wall clock, and is what lets --record auto tell a site-only repo from a
// deploy-only one.
const [siteRet, deployRet, servedRes] = await Promise.all([
  rpc("eth_call", [{ to: opts.registry, data: encodeGet(keys.site) }, "latest"]),
  rpc("eth_call", [{ to: opts.registry, data: encodeGet(keys.deploy) }, "latest"]),
  fetch(`${gateway}/site/${repo}/${path}`),
]);
const records = { site: decodeGet(siteRet), deploy: decodeGet(deployRet) };

// What the canister actually served.
if (!servedRes.ok) {
  console.error(`fetch ${gateway}/site/${repo}/${path}: HTTP ${servedRes.status}`);
  process.exit(1);
}
const served = Buffer.from(await servedRes.arrayBuffer());

// A deploy record attests sha256 of the DECODED contract bytecode, so check B
// needs the hex form for that kind. This is a property of the record, never of
// the artifact: a site page whose entire content happens to be an even number
// of hex characters is still hashed raw by the publisher.
const servedText = served.toString("utf8").trim();
const hexBody = servedText.startsWith("0x") ? servedText.slice(2) : servedText;
const isHexText = /^[0-9a-fA-F]+$/.test(hexBody) && hexBody.length % 2 === 0;

function resolveRecord() {
  if (opts.record !== "auto") return opts.record;
  if (records.site.present && !records.deploy.present) return "site";
  if (records.deploy.present && !records.site.present) return "deploy";
  if (records.site.present && records.deploy.present) {
    // Both exist (a repo that deploys a contract AND serves a site). Guessing
    // from the artifact's shape gets a hex-looking site page wrong, and picking
    // whichever record happens to match would turn check B into "matches
    // something". Ask instead: only the caller knows which one they meant.
    console.error(`"${repo}" has both a site and a deploy record; pass --record site or --record deploy`);
    process.exit(2);
  }
  // Neither present. Pick by artifact form purely so the error below names the
  // key the caller most likely meant.
  return isHexText ? "deploy" : "site";
}
const kind = resolveRecord();
const recordKey = keys[kind];
const record = records[kind];
if (!record.present) {
  console.error(`no registry entry for key "${recordKey}" at ${opts.registry}`);
  const other = kind === "site" ? "deploy" : "site";
  if (records[other].present) {
    console.error(`(a ${other} record exists for this repo; try --record ${other})`);
  }
  process.exit(1);
}
const { commit: registryCommit, bundleHash: registryBundleHash, updatedAt } = record;
console.log(`registry: key "${recordKey}" (${kind} record)`);
console.log(`registry: commit ${registryCommit}`);
console.log(`registry: bundleHash ${registryBundleHash}`);
console.log(`registry: updatedAt ${new Date(updatedAt * 1000).toISOString()}`);

const servedCommit = servedRes.headers.get("x-ic-git-commit") ?? "";
// Where the served bytes live in the commit tree (site root + index.html
// fallback applied by the canister); the git-clone check must use this, not
// the URL path. Fallback for canisters predating the header.
const servedPath = servedRes.headers.get("x-ic-git-path") ?? path;
console.log(`served: ${served.length} bytes, X-Ic-Git-Commit ${servedCommit}, tree path ${servedPath}`);

// --- checks ------------------------------------------------------------------

// A. The served response claims exactly the attested commit.
const commitOk = servedCommit === registryCommit;
report(commitOk, "A: served commit == registry commit", commitOk ? "" : `served ${servedCommit || "(none)"}`);

// B. The artifact hashes to the attested bundleHash, hashed the way THIS
// record's publisher hashed it: provenance::deploy_record hashes the decoded
// contract bytecode, provenance::site_record hashes the served bytes exactly
// as delivered (both then write through evm::registry_publish_record).
// Choosing by the artifact's shape instead would mis-hash a site
// page that is all hex characters and report a correctly served page as
// unverified.
const wantsHex = kind === "deploy";
const hashed = wantsHex && isHexText ? Buffer.from(hexBody, "hex") : served;
const artifactHash = sha256(hashed);
const hashOk = artifactHash === registryBundleHash;
report(
  hashOk,
  `B: sha256(${wantsHex ? "hex-decoded" : "raw"} artifact) == registry bundleHash`,
  hashOk
    ? ""
    : wantsHex && !isHexText
      ? "a deploy record attests hex-decoded bytecode, but the served artifact is not hex text"
      : `artifact ${artifactHash}`
);

// C. Advisory: on-chain runtime code should be a trailing slice of the
// attested creation bytecode. Only a deploy record attests creation bytecode;
// against a site record `hashed` is page content, so comparing it would be
// meaningless rather than merely failing.
if (opts.contract && !wantsHex) {
  report(false, "C: --contract needs a deploy record", `resolved the ${kind} record; pass --record deploy`);
} else if (opts.contract) {
  const code = (await rpc("eth_getCode", [opts.contract, "latest"])).slice(2).toLowerCase();
  const creation = hashed.toString("hex").toLowerCase();
  report(
    code.length > 0 && creation.endsWith(code),
    "C: eth_getCode(contract) is a trailing slice of the creation bytecode",
    code.length === 0 ? "no code at address" : ""
  );
}

// D. Independent re-derivation: clone the repo from the canister and compare
// the blob at <commit>:<path> with what was served.
try {
  execFileSync("git", ["--version"], { stdio: "ignore" });
  const dir = mkdtempSync(join(tmpdir(), "icgit-verify-"));
  try {
    execFileSync(
      "git",
      ["clone", "--quiet", "--no-checkout", `${gateway}/${repo}.git`, dir],
      { stdio: ["ignore", "ignore", "pipe"] }
    );
    const blob = execFileSync(
      "git",
      ["-C", dir, "show", `${servedCommit}:${servedPath}`],
      { maxBuffer: 64 * 1024 * 1024 }
    );
    report(
      Buffer.compare(blob, served) === 0,
      "D: git clone reproduces the served bytes at the attested commit"
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
} catch (e) {
  report(false, "D: git clone reproduces the served bytes", e.message.split("\n")[0]);
}

// E. A matching hash proves the entrypoint, not the page. Only meaningful for
// a site record -- a deploy record's artifact is bytecode, not a page.
if (kind === "site") {
  const reason = unverifiableSubresource(servedPath, served);
  report(
    reason === null,
    "E: entrypoint references are enforceable (self-contained or SRI-pinned)",
    reason ?? ""
  );
}

console.log(failures === 0 ? "\nVERIFIED" : `\nNOT VERIFIED (${failures} failing check${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
