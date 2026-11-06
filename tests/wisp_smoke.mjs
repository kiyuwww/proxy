// Smoke test for the Wisp endpoint (requires a logged-in session).
// Usage:  SID=<session token> node tests/wisp_smoke.mjs <port> [echoPort]
//   - get SID by logging in (the "sid" cookie value) and copying it.
//   - echoPort is optional; the loopback check needs ALLOW_LOOPBACK_IPS=1 on the server.
import net from "node:net";

const [port, echoPort] = [process.argv[2] || 8080, process.argv[3]];
const CONNECT = 0x01, DATA = 0x02, CONTINUE = 0x03, CLOSE = 0x04;

function pkt(type, sid, payload = Buffer.alloc(0)) {
  const h = Buffer.alloc(5);
  h.writeUInt8(type, 0);
  h.writeUInt32LE(sid, 1);
  return Buffer.concat([h, payload]);
}
function connectPayload(port, host) {
  const b = Buffer.alloc(3 + host.length);
  b.writeUInt8(0x01, 0);            // TCP
  b.writeUInt16LE(port, 1);
  b.write(host, 3);
  return b;
}

function open() {
  if (!process.env.SID) throw new Error("set SID to a valid session token");
  const ws = new WebSocket(`ws://127.0.0.1:${port}/wisp/`, { headers: { Cookie: `sid=${process.env.SID}` } });
  ws.binaryType = "arraybuffer";
  const queue = [];
  let waiter = null;
  ws.onmessage = (e) => {
    const b = Buffer.from(e.data);
    const p = { type: b.readUInt8(0), sid: b.readUInt32LE(1), payload: b.subarray(5) };
    if (waiter) { const w = waiter; waiter = null; w(p); } else queue.push(p);
  };
  const next = (pred, ms = 5000) => new Promise((resolve, reject) => {
    const idx = queue.findIndex(pred);
    if (idx >= 0) return resolve(queue.splice(idx, 1)[0]);
    const timer = setTimeout(() => reject(new Error("timeout waiting for packet")), ms);
    const check = (p) => { if (pred(p)) { clearTimeout(timer); resolve(p); } else { queue.push(p); waiter = check; } };
    waiter = check;
  });
  return new Promise((resolve, reject) => {
    ws.onopen = () => resolve({ ws, next });
    ws.onerror = () => reject(new Error("websocket error"));
  });
}

let failures = 0;
function check(name, cond, extra = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name} ${extra}`);
  if (!cond) failures++;
}

const { ws, next } = await open();
// Wisp v1 handshake: the first message must be CONTINUE on stream 0 (see wisp_session.cpp).
const win = await next((p) => p.type === CONTINUE && p.sid === 0);
check("first handshake packet is CONTINUE window=128", win.payload.readUInt32LE(0) === 128);

// 1) Blocked by hostname blacklist (no DNS lookup performed)
ws.send(pkt(CONNECT, 1, connectPayload(80, "www.example.com")));
const blocked = await next((p) => p.type === CLOSE && p.sid === 1);
check("blacklisted host -> CLOSE 0x48", blocked.payload[0] === 0x48, `(reason=0x${blocked.payload[0].toString(16)})`);

// 2) Loopback target: allowed only when ALLOW_LOOPBACK_IPS=1
if (echoPort) {
  ws.send(pkt(CONNECT, 2, connectPayload(Number(echoPort), "127.0.0.1")));
  ws.send(pkt(DATA, 2, Buffer.from("hello-wisp")));
  const echo = await next((p) => p.type === DATA && p.sid === 2 && p.payload.toString() === "hello-wisp", 5000)
    .catch(() => null);
  check("loopback echo through stream (needs ALLOW_LOOPBACK_IPS=1)", !!echo);
  ws.send(pkt(CLOSE, 2, Buffer.from([0x02])));
}

// 3) Public target: real HTTP request via 1.1.1.1 (needs internet from the sandbox)
ws.send(pkt(CONNECT, 3, connectPayload(80, "1.1.1.1")));
ws.send(pkt(DATA, 3, Buffer.from("HEAD / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n")));
const resp = await next((p) => p.type === DATA && p.sid === 3, 8000).catch(() => null);
check("public IP stream returns HTTP data", !!resp, resp ? `(${resp.payload.toString().split("\r\n")[0]})` : "");

// 4) Private IP must be refused regardless of ALLOW flags unless explicitly enabled
ws.send(pkt(CONNECT, 4, connectPayload(80, "10.0.0.1")));
const priv = await next((p) => p.type === CLOSE && p.sid === 4, 8000).catch(() => null);
check("private IP 10.0.0.1 blocked (CLOSE 0x48)", !!priv && priv.payload[0] === 0x48);

ws.close();
console.log(failures ? `\n${failures} check(s) FAILED` : "\nall checks passed");
process.exit(failures ? 1 : 0);
