// Relay throughput + data integrity test.
// Start the server with ALLOW_LOOPBACK_IPS=1, then:
//   SERVER_PID=<pid> node tests/throughput.mjs <port> [megabytes=32] [streams=1]
// Sends random data through the Wisp endpoint to a local echo server, verifies every
// echoed byte, and reports MB/s and the server's CPU seconds per MB relayed.
import net from "node:net";
import fs from "node:fs";
import crypto from "node:crypto";

const PORT = Number(process.argv[2] || 8080);
const MB = Number(process.argv[3] || 32);
const STREAMS = Number(process.argv[4] || 1);
const BASE = `http://127.0.0.1:${PORT}`;
const CONNECT = 1, DATA = 2, CONTINUE = 3, CLOSE = 4;
const CHUNK = 16 * 1024;

const cpuSeconds = () => {
  if (!process.env.SERVER_PID) return NaN;
  const f = fs.readFileSync(`/proc/${process.env.SERVER_PID}/stat`, "utf8").split(" ");
  return (Number(f[13]) + Number(f[14])) / 100;
};

const name = "tp_" + Math.random().toString(36).slice(2, 8);
const res = await fetch(BASE + "/api/register", { method: "POST", headers: { Origin: BASE }, body: new URLSearchParams({ username: name, password: "throughput-pw-1" }) });
const SID = /sid=([0-9a-f]+)/.exec(res.headers.get("set-cookie") || "")?.[1];
if (!SID) { console.log("register failed", res.status); process.exit(2); }

const echo = net.createServer((s) => { s.on("data", (d) => s.write(d)); s.on("error", () => {}); });
await new Promise((r) => echo.listen(0, "127.0.0.1", r));
const ECHO = echo.address().port;

const ws = new WebSocket(`ws://127.0.0.1:${PORT}/wisp/`, { headers: { Cookie: `sid=${SID}` } });
ws.binaryType = "arraybuffer";
await new Promise((r) => (ws.onopen = r));

const streams = new Map(); // sid -> state
let maxWindow = 128;
function pkt(type, sid, payload) {
  const h = Buffer.alloc(5); h.writeUInt8(type, 0); h.writeUInt32LE(sid, 1);
  return payload ? Buffer.concat([h, payload]) : h;
}
function pump(st) {
  while (st.window > 0 && st.sent < st.total) {
    const n = Math.min(CHUNK, st.total - st.sent);
    const chunk = crypto.randomBytes(n);
    st.sentHash.update(chunk);
    ws.send(pkt(DATA, st.sid, chunk));
    st.sent += n; st.window--;
  }
}
const done = new Promise((resolve) => {
  ws.onmessage = (e) => {
    const b = Buffer.from(e.data);
    const type = b[0], sid = b.readUInt32LE(1);
    if (type === CONTINUE && sid === 0) { maxWindow = b.readUInt32LE(5); return; }
    const st = streams.get(sid);
    if (!st) return;
    if (type === CONTINUE) { st.window = b.readUInt32LE(5); pump(st); }
    else if (type === DATA) {
      const payload = b.subarray(5);
      st.recvHash.update(payload); st.recv += payload.length;
      if (st.recv >= st.total && !st.finished) { st.finished = true; if ([...streams.values()].every((s) => s.finished)) resolve(); }
    } else if (type === CLOSE) { st.finished = true; st.error = `closed by server (reason 0x${b[5].toString(16)})`; if ([...streams.values()].every((s) => s.finished)) resolve(); }
  };
});

await new Promise((r) => setTimeout(r, 200));
const total = MB * 1024 * 1024 / STREAMS;
for (let i = 1; i <= STREAMS; i++) {
  const host = Buffer.from("127.0.0.1");
  const payload = Buffer.alloc(3 + host.length); payload.writeUInt8(1, 0); payload.writeUInt16LE(ECHO, 1); host.copy(payload, 3);
  streams.set(i, { sid: i, total, sent: 0, recv: 0, window: maxWindow, sentHash: crypto.createHash("sha256"), recvHash: crypto.createHash("sha256"), finished: false });
  ws.send(pkt(CONNECT, i, payload));
}
const cpu0 = cpuSeconds(); const t0 = Date.now();
for (const st of streams.values()) pump(st);
const timeout = setTimeout(() => { console.log("TIMEOUT: transfer did not finish in 300s"); process.exit(1); }, 300000);
await done; clearTimeout(timeout);
const secs = (Date.now() - t0) / 1000; const cpu = cpuSeconds() - cpu0;
let ok = true;
for (const st of streams.values()) {
  const same = st.error ? false : st.sentHash.digest("hex") === st.recvHash.digest("hex") && st.sent === st.recv;
  if (!same) { ok = false; console.log(`stream ${st.sid}: MISMATCH ${st.error || ""} sent=${st.sent} recv=${st.recv}`); }
}
const moved = MB * 2; // up + down
console.log(`${ok ? "PASS" : "FAIL"}  ${MB} MB up + ${MB} MB down over ${STREAMS} stream(s): integrity ${ok ? "verified" : "BROKEN"}`);
console.log(`      time ${secs.toFixed(1)} s  ->  ${(moved / secs).toFixed(1)} MB/s total relayed`);
if (!Number.isNaN(cpu)) console.log(`      server CPU ${cpu.toFixed(2)} s  ->  ${(cpu / moved * 1000).toFixed(0)} ms CPU per MB relayed`);
ws.close(); echo.close();
process.exit(ok ? 0 : 1);
