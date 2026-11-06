// Hostile-input and stress tests. Needs Node 22+ (global WebSocket with headers).
//
// Start the server with:  ALLOW_LOOPBACK_IPS=1 MAX_STREAMS=50 COOKIE_SECURE=0 PORT=<port> ...
// Run:  SERVER_PID=<pid> node tests/robustness.mjs <port>
//
// The test spins up its own TCP helper servers on 127.0.0.1 (echo, black hole).
import net from "node:net";
import fs from "node:fs";

const PORT = Number(process.argv[2] || 8080);
const BASE = `http://127.0.0.1:${PORT}`;
const SERVER_PID = process.env.SERVER_PID;
const HEALTH = process.env.HEALTH_PATH || "/healthz";
const CONNECT = 1, DATA = 2, CONTINUE = 3, CLOSE = 4;

let failures = 0;
function check(name, cond, extra = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name} ${extra}`);
  if (!cond) failures++;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rssMB = () => {
  if (!SERVER_PID) return NaN;
  try {
    const m = /VmRSS:\s+(\d+)/.exec(fs.readFileSync(`/proc/${SERVER_PID}/status`, "utf8"));
    return Math.round(Number(m[1]) / 1024);
  } catch { return NaN; }
};
async function alive() {
  try { return (await fetch(BASE + HEALTH, { signal: AbortSignal.timeout(4000) })).ok; } catch { return false; }
}

function pkt(type, sid, payload = Buffer.alloc(0)) {
  const h = Buffer.alloc(5);
  h.writeUInt8(type, 0); h.writeUInt32LE(sid >>> 0, 1);
  return Buffer.concat([h, payload]);
}
function connectPayload(port, host, stype = 1) {
  const h = Buffer.from(host);
  const b = Buffer.alloc(3 + h.length);
  b.writeUInt8(stype, 0); b.writeUInt16LE(port, 1); h.copy(b, 3);
  return b;
}

// --- accounts -------------------------------------------------------------
async function api(path, fields, headers = {}) {
  const res = await fetch(BASE + path, {
    method: fields ? "POST" : "GET",
    headers: { Origin: BASE, ...headers },
    body: fields ? new URLSearchParams(fields) : undefined,
    redirect: "manual",
  });
  let data = {}; try { data = await res.json(); } catch {}
  return { status: res.status, data, cookie: res.headers.get("set-cookie") };
}
const rnd = () => Math.random().toString(36).slice(2, 8);
const user = "rb_" + rnd();
const pass = "pw-" + rnd() + "-ok";
const reg = await api("/api/register", { username: user, password: pass });
const SID = /sid=([0-9a-f]+)/.exec(reg.cookie || "")?.[1];
if (!SID) { console.log("cannot register test user", reg); process.exit(2); }

function openWs() {
  const ws = new WebSocket(`ws://127.0.0.1:${PORT}/wisp/`, { headers: { Cookie: `sid=${SID}` } });
  ws.binaryType = "arraybuffer";
  const q = []; let waiter = null; let closed = false;
  ws.onmessage = (e) => {
    const b = Buffer.from(e.data);
    const p = { type: b[0], sid: b.readUInt32LE(1), payload: b.subarray(5) };
    if (waiter) { const w = waiter; waiter = null; w(p); } else q.push(p);
  };
  ws.onclose = () => { closed = true; if (waiter) { const w = waiter; waiter = null; w(null); } };
  const next = (pred, ms = 4000) => new Promise((resolve) => {
    const i = q.findIndex(pred);
    if (i >= 0) return resolve(q.splice(i, 1)[0]);
    const t = setTimeout(() => { waiter = null; resolve(null); }, ms);
    const check_ = (p) => { if (p === null) { clearTimeout(t); resolve(null); } else if (pred(p)) { clearTimeout(t); resolve(p); } else { q.push(p); waiter = check_; } };
    waiter = check_;
  });
  return new Promise((resolve, reject) => {
    ws.onopen = () => resolve({ ws, next, isClosed: () => closed, q });
    ws.onerror = () => reject(new Error("ws open failed"));
  });
}

// --- helper TCP servers ---------------------------------------------------
const echoSockets = new Set();
const echo = net.createServer((s) => { echoSockets.add(s); s.on("data", (d) => s.write(d)); s.on("close", () => echoSockets.delete(s)); s.on("error", () => {}); });
await new Promise((r) => echo.listen(0, "127.0.0.1", r));
const ECHO = echo.address().port;
const holeSockets = new Set();
const hole = net.createServer((s) => { holeSockets.add(s); s.pause(); s.on("close", () => holeSockets.delete(s)); s.on("error", () => {}); });
await new Promise((r) => hole.listen(0, "127.0.0.1", r));
const HOLE = hole.address().port;

const rss0 = rssMB();
console.log(`server RSS at start: ${rss0} MB`);

// ===== 1. malformed Wisp packets: server must stay up and keep the session =====
{
  const { ws, next } = await openWs();
  await next((p) => p.type === CONTINUE && p.sid === 0);
  ws.send(Buffer.alloc(0));
  ws.send(Buffer.from([1, 2, 3, 4]));                               // shorter than a header
  ws.send(pkt(0x77, 1));                                            // unknown type
  ws.send(pkt(CONNECT, 1, Buffer.from([1, 80])));                   // CONNECT payload too short
  ws.send(pkt(DATA, 999, Buffer.from("x")));                        // DATA for unknown stream
  ws.send(pkt(CLOSE, 999, Buffer.from([2])));                       // CLOSE for unknown stream
  ws.send(pkt(CONTINUE, 5, Buffer.from([1, 0, 0, 0])));             // client CONTINUE: not allowed, ignored
  ws.send("this is a text frame");                                  // text frames are ignored
  ws.send(pkt(CONNECT, 2, connectPayload(80, "www.example.com"))); // blacklisted
  const c = await next((p) => p.type === CLOSE && p.sid === 2);
  check("session survives malformed packets", !!c && c.payload[0] === 0x48);
  ws.send(pkt(CONNECT, 3, connectPayload(80, "")));                 // empty hostname
  const c3 = await next((p) => p.type === CLOSE && p.sid === 3);
  check("empty hostname refused", !!c3);
  ws.send(pkt(CONNECT, 4, connectPayload(80, "x".repeat(60000)))); // enormous hostname
  const c4 = await next((p) => p.type === CLOSE && p.sid === 4, 8000);
  check("60KB hostname refused without crash", !!c4, `(reason=${c4 ? "0x" + c4.payload[0].toString(16) : "none"})`);
  ws.send(pkt(CONNECT, 5, connectPayload(80, "::1")));              // IPv6 loopback literal (server allows loopback in this test run)
  ws.send(pkt(CONNECT, 6, connectPayload(80, "999.999.999.999"))); // not an IP, not resolvable
  const c6 = await next((p) => p.type === CLOSE && p.sid === 6, 10000);
  check("invalid address refused", !!c6);
  ws.send(pkt(CONNECT, 7, connectPayload(80, "10.1.2.3", 2)));      // UDP stream type
  const c7 = await next((p) => p.type === CLOSE && p.sid === 7);
  check("UDP stream refused (0x48)", !!c7 && c7.payload[0] === 0x48);
  ws.close();
}
check("server alive after malformed packets", await alive());

// ===== 2. oversized websocket message =====
{
  const { ws, next, isClosed } = await openWs();
  await next((p) => p.type === CONTINUE && p.sid === 0);
  ws.send(Buffer.alloc(8 * 1024 * 1024, 7));
  await sleep(1500);
  check("8MB message makes the server drop the session", isClosed());
}
check("server alive after oversized message", await alive());

// ===== 3. stream limit (MAX_STREAMS=50) =====
{
  const { ws, next } = await openWs();
  await next((p) => p.type === CONTINUE && p.sid === 0);
  for (let i = 1; i <= 80; i++) ws.send(pkt(CONNECT, i, connectPayload(ECHO, "127.0.0.1")));
  let throttled = 0;
  for (let i = 0; i < 30; i++) { const c = await next((p) => p.type === CLOSE && p.payload[0] === 0x49, 2000); if (c) throttled++; else break; }
  check("streams beyond MAX_STREAMS are throttled (0x49)", throttled === 30, `(got ${throttled}/30 CLOSE 0x49)`);
  ws.close();
  await sleep(800);
  check("closing the websocket closes all upstream TCP sockets", echoSockets.size === 0, `(open echo sockets: ${echoSockets.size})`);
}

// ===== 4. abrupt disconnect churn: 100 sessions x 20 streams =====
{
  for (let round = 0; round < 100; round++) {
    const { ws, next } = await openWs();
    await next((p) => p.type === CONTINUE && p.sid === 0);
    for (let i = 1; i <= 20; i++) { ws.send(pkt(CONNECT, i, connectPayload(ECHO, "127.0.0.1"))); ws.send(pkt(DATA, i, Buffer.from("ping"))); }
    ws.close();
  }
  await sleep(2000);
  check("no leaked upstream sockets after 100 abrupt disconnects", echoSockets.size === 0, `(open: ${echoSockets.size})`);
  check("server alive after churn", await alive());
}

// ===== 5. data flood to a peer that never reads (memory must stay bounded) =====
{
  const before = rssMB();
  const { ws, next } = await openWs();
  await next((p) => p.type === CONTINUE && p.sid === 0);
  ws.send(pkt(CONNECT, 1, connectPayload(HOLE, "127.0.0.1")));
  await sleep(300);
  const chunk = Buffer.alloc(60 * 1024, 1);
  let sent = 0;
  for (let i = 0; i < 3000; i++) { ws.send(pkt(DATA, 1, chunk)); sent += chunk.length; if (i % 100 === 0) await sleep(5); }
  await sleep(1500);
  const closed = await next((p) => p.type === CLOSE && p.sid === 1, 3000);
  const after = rssMB();
  console.log(`  flooded ${(sent / 1048576).toFixed(0)} MB into a stalled peer; RSS ${before} -> ${after} MB`);
  check("stalled peer: stream is closed instead of buffering forever", !!closed);
  check("stalled peer: memory growth under 40 MB", Number.isNaN(after) || after - before < 40, `(+${after - before} MB)`);
  ws.close();
}

// ===== 6. hostile HTTP =====
function raw(data, { wait = 1500, end = false } = {}) {
  return new Promise((resolve) => {
    const s = net.connect(PORT, "127.0.0.1");
    let out = Buffer.alloc(0);
    s.on("data", (d) => (out = Buffer.concat([out, d])));
    s.on("error", () => {});
    s.on("close", () => resolve({ out: out.toString("latin1"), closed: true }));
    s.on("connect", () => { s.write(data); if (end) s.end(); });
    setTimeout(() => { const o = out.toString("latin1"); s.destroy(); resolve({ out: o, closed: false }); }, wait);
  });
}
{
  const g = await raw("GARBAGE\r\n\r\n");
  check("garbage request does not crash the server", await alive(), `(reply: ${JSON.stringify(g.out.slice(0, 20))})`);
  const big = await raw("GET / HTTP/1.1\r\nHost: x\r\nX-Pad: " + "a".repeat(40000) + "\r\n\r\n");
  check("40KB header rejected", !/^HTTP\/1\.1 200/.test(big.out));
  const body = await raw("POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n" + "a".repeat(100000));
  check("100KB POST body rejected", !/^HTTP\/1\.1 200/.test(body.out));
  const paths = ["/../../etc/passwd", "//etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/index.html%00.png", "/public/../index.css", "/.env", "/src/main.cpp", "/scram/../.env"];
  let leaked = false;
  for (const p of paths) {
    const r = await raw(`GET ${p} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`, { wait: 600 });
    if (/root:|DATABASE_URL|int main/.test(r.out)) leaked = true;
  }
  check("path traversal / hidden files not served", !leaked);
  const head = await raw("HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", { wait: 800 });
  check("HEAD / returns 200 with no body", /^HTTP\/1\.1 200/.test(head.out) && head.out.split("\r\n\r\n")[1] === "", `(${head.out.split("\r\n")[0]})`);
  const opt = await raw("OPTIONS / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", { wait: 800 });
  check("OPTIONS gets 405", /^HTTP\/1\.1 405/.test(opt.out));
  let pipeline = "";
  for (let i = 0; i < 50; i++) pipeline += `GET ${HEALTH} HTTP/1.1\r\nHost: x\r\n\r\n`;
  const pl = await raw(pipeline, { wait: 2000 });
  const answers = (pl.out.match(/HTTP\/1\.1 200/g) || []).length;
  check("50 pipelined requests answered", answers === 50, `(${answers}/50)`);
  const t0 = Date.now();
  const slow = await raw("GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ", { wait: 20000 });
  check("slowloris connection is dropped by the server within 20s", slow.closed, `(after ${Math.round((Date.now() - t0) / 1000)}s)`);
}

// ===== 7. auth API with hostile input =====
{
  const inj = await api("/api/register", { username: "' OR 1=1 --", password: pass });
  check("SQL-looking username rejected", inj.status === 400);
  const uni = await api("/api/register", { username: "юзер_1", password: pass });
  check("non-latin username rejected", uni.status === 400);
  const long = await api("/api/register", { username: "rb_" + rnd(), password: "p".repeat(129) });
  check("129-char password rejected", long.status === 400);
  const noFields = await api("/api/login", {});
  check("login with no fields rejected", noFields.status === 401 || noFields.status === 400);
  const evilPass = "x'; DROP TABLE users;-- ok";
  const u2 = "rb_" + rnd();
  const r2 = await api("/api/register", { username: u2, password: evilPass });
  const l2 = await api("/api/login", { username: u2, password: evilPass });
  check("password with SQL characters works (parameterized)", r2.status === 200 && l2.status === 200);
  const same = "rb_" + rnd();
  const results = await Promise.all(Array.from({ length: 20 }, () => api("/api/register", { username: same, password: pass })));
  const ok = results.filter((r) => r.status === 200).length;
  const dup = results.filter((r) => r.status === 409).length;
  const limited = results.filter((r) => r.status === 429 || r.status === 503).length; // per-IP register limit / busy queue
  check("20 parallel registrations of one name: at most one wins, rest 409/429/503", ok <= 1 && ok + dup + limited === 20, `(200:${ok} 409:${dup} limited:${limited})`);
  const xo = await fetch(BASE + "/api/login", { method: "POST", headers: { Origin: "https://evil.example" }, body: new URLSearchParams({ username: user, password: pass }) });
  check("cross-origin login POST refused", xo.status === 403);
  const badTok = await fetch(BASE + "/api/me", { headers: { Cookie: "sid=" + "0".repeat(64) } });
  check("random valid-format token is not accepted", badTok.status === 401);
  const junkTok = await fetch(BASE + "/api/me", { headers: { Cookie: "sid=' or 1=1 --" } });
  check("junk token is not accepted", junkTok.status === 401);
}

// ===== 8. many idle connections =====
{
  const socks = [];
  for (let i = 0; i < 300; i++) socks.push(net.connect(PORT, "127.0.0.1").on("error", () => {}));
  await sleep(1500);
  check("server responsive with 300 idle connections", await alive());
  socks.forEach((s) => s.destroy());
}

const rss1 = rssMB();
console.log(`server RSS at end: ${rss1} MB (start ${rss0} MB)`);
check("no unbounded memory growth (< 60 MB over the run)", Number.isNaN(rss1) || rss1 - rss0 < 60, `(+${rss1 - rss0} MB)`);
echo.close(); hole.close();
console.log(failures ? `\n${failures} check(s) FAILED` : "\nall checks passed");
process.exit(failures ? 1 : 0);
