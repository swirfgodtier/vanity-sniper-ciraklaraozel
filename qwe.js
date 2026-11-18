"use strict";
import http2 from "node:http2";
import tls from "node:tls";
import fs from "node:fs";
import path from "node:path";
import { cpus } from "node:os";
import WebSocket from "ws";


process.env.UV_THREADPOOL_SIZE = String(cpus().length * 4);


const CONFIG = {
  token: "",
  guildId: "1543574720664969216",
  mfaPath: "./mfa.txt",
  host: "canary.discord.com",
  tlsConnections: 11,
  h2Connections: 11,
};

const TLS_COUNT = CONFIG.tlsConnections;
const H2_COUNT = CONFIG.h2Connections || 4;
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const XPROPS = "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzMS4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTMxLjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjM3MTM2MCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0=";

let mfaToken = null;
const trackedVanities = new Map();

function rebuildAllCache() {
  const entries = Array.from(trackedVanities.entries());
  trackedVanities.clear();
  for (const [gid, val] of entries) {
    const code = val.code || val;
    trackedVanities.set(gid, buildRequest(code));
  }
  if (entries.length > 0) {
    console.log(`[MFA] Eski cache temizlendi ve ${entries.length} sunucu için yeni body/request cache build edildi.`);
  }
}

async function readMfa() {
  try {
    let newMfa = null;
    const pathsToTry = [
      CONFIG.mfaPath,
      "./mfa.txt",
      "mfa.txt",
      ...(import.meta.dirname ? [path.join(import.meta.dirname, "mfa.txt"), path.join(import.meta.dirname, CONFIG.mfaPath)] : [])
    ];
    for (const p of pathsToTry) {
      if (typeof Bun !== "undefined" && Bun.file) {
        const file = Bun.file(p);
        if (await file.exists()) {
          const data = (await file.text()).trim();
          newMfa = data.split("\n")[0]?.trim() || null;
          if (newMfa) break;
        }
      } else if (fs.existsSync(p)) {
        const data = fs.readFileSync(p, "utf8").trim();
        newMfa = data.split("\n")[0]?.trim() || null;
        if (newMfa) break;
      }
    }

    if (newMfa && newMfa !== mfaToken) {
      mfaToken = newMfa;
      rebuildAllCache();
    }
  } catch { }
}
readMfa();

try {
  const mfaFile = fs.existsSync(CONFIG.mfaPath) ? CONFIG.mfaPath : "mfa.txt";
  if (fs.existsSync(mfaFile)) {
    fs.watch(mfaFile, (e) => {
      if (e === "change" || e === "rename") readMfa();
    });
  }
} catch { }

let tlsSession = null;
const tlsSocks = new Array(TLS_COUNT).fill({ write() { }, destroyed: true });
const tlsBackoff = new Array(TLS_COUNT).fill(500);
const tlsStarts = new Array(TLS_COUNT).fill(0n);

const h2Conns = new Array(H2_COUNT);

let activeTargetVanity = null;

const createH2Session = (i) => {
  const session = http2.connect(`https://${CONFIG.host}:443`, {
    maxVersion: "TLSv1.3",
    minVersion: "TLSv1.3",
    ciphers: "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
    ecdhCurve: "X25519",
    ALPNProtocols: ["h2"],
    rejectUnauthorized: false,
    highWaterMark: 32 * 1024,
    peerMaxConcurrentStreams: 1000,
    paddingStrategy: http2.constants.PADDING_STRATEGY_NONE,
    maxConcurrentStreams: 200,
    enablePush: false,
    initialWindowSize: 4 * 1024 * 1024,
    maxFrameSize: 4 * 1024 * 1024,
    headerTableSize: 16384,
    maxHeaderListSize: 32768
  });
  session.ref();
  session.once("connect", () => {
    console.log(`[HTTP2] Session ${i} connected`);
    try {
      const req = session.request({
        ":method": "GET",
        ":path": "/api/v9/gateway",
        ":scheme": "https",
        ":authority": CONFIG.host
      });
      req.on("error", () => {});
      req.end();
    } catch (e) {}
  });

  let isReconnecting = false;
  const reconnect = () => {
    if (isReconnecting) return;
    isReconnecting = true;
    try { session.destroy(); } catch {}
    setTimeout(() => { h2Conns[i] = createH2Session(i); }, 200);
  };

  session.on("error", () => reconnect());
  session.on("close", () => reconnect());
  return session;
};

function createTLS(i) {
  const s = tls.connect({
    host: CONFIG.host || "discord.com",
    port: 443,
    servername: CONFIG.host || "discord.com",
    minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3",
    ciphers: "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
    sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
    ecdhCurve: "X25519:prime256v1:secp384r1",
    ALPNProtocols: ["http/1.1"],
    rejectUnauthorized: false,
    honorCipherOrder: true,
    session: tlsSession,
    highWaterMark: 1024 * 1024,
    handshakeTimeout: 4000,
    timeout: 0
  });

  s.setNoDelay(true);
  s.setKeepAlive(true, 15000);
  s.on("session", sess => { tlsSession = sess; });
  s.on("secureConnect", () => {
    tlsSocks[i] = s;
    tlsBackoff[i] = 500;
  });

  s.on("data", buf => {
    const now = process.hrtime.bigint();
    const start = tlsStarts[i] || now;
    const diffMs = (Number(now - start) / 1e6).toFixed(2);

    try {
      const raw = buf.toString("latin1");
      const parts = raw.split(/(?=HTTP\/\d\.\d)/g);
      for (const part of parts) {
        if (!part.startsWith("HTTP/")) continue;
        const line = part.split("\r\n")[0] || "";
        const status = parseInt(line.split(" ")[1], 10) || 0;
        const body = part.split("\r\n\r\n")[1] || "";

        let json = null;
        try {
          json = JSON.parse(body);
        } catch { }

        if (status >= 100 && status < 600) {
          const isSuccess = (status === 200 || status === 204) &&
            ((activeTargetVanity && json && typeof json.code === "string" && json.code.toLowerCase() === activeTargetVanity.toLowerCase()) ||
              (activeTargetVanity && body.includes(`"${activeTargetVanity}"`)) ||
              (json && typeof json.code === "string" && isNaN(Number(json.code))));

          if (isSuccess) {
            console.log(`\x1b[32m[SUCCESS] tls[${i}]: HTTP ${status} [${diffMs}ms] - Vanity alındı! ${JSON.stringify(json || body)}\x1b[0m`);
          } else if (json && json.code !== undefined) {
            console.log(`tls[${i}]: HTTP ${status} [${diffMs}ms] ${JSON.stringify(json)}`);
          } else if (activeTargetVanity) {
            console.log(`tls[${i}]: HTTP ${status} [${diffMs}ms] ${json ? JSON.stringify(json) : body.slice(0, 200)}`);
          }
        }
      }
    } catch { }
  });

  s.on("timeout", () => { s.destroy(); });
  s.on("error", () => { });
  s.on("close", () => {
    tlsSocks[i] = { write() { }, destroyed: true };
    setTimeout(() => createTLS(i), tlsBackoff[i]);
    tlsBackoff[i] = Math.min(tlsBackoff[i] * 2, 5000);
  });
}

function buildRequest(vanity) {
  const body = '{"code":"' + vanity + '"}';
  const len = Buffer.byteLength(body);

  const buildTlsBuf = (mfa) => {
    let req =
      `PATCH /api/v9/guilds/${CONFIG.guildId}/vanity-url HTTP/1.1\r\n` +
      `Host: ${CONFIG.host}\r\n` +
      `Authorization: ${CONFIG.token}\r\n`;
    if (mfa) req += `X-Discord-Mfa-Authorization: ${mfa}\r\n`;
    req +=
      `Content-Type: application/json\r\n` +
      `Accept-Encoding: identity\r\n` +
      `User-Agent: ${UA}\r\n` +
      `X-Super-Properties: ${XPROPS}\r\n` +
      `Content-Length: ${len}\r\n\r\n` + body;
    return Buffer.from(req, "latin1");
  };

  return {
    code: vanity,
    get buffer() { return buildTlsBuf(mfaToken); },
    fire: () => {
      activeTargetVanity = vanity;
      readMfa();
      const tlsBuf = buildTlsBuf(mfaToken);

      for (let i = h2Conns.length - 1; i >= 0; i--) {
        try {
          if (!h2Conns[i] || h2Conns[i].destroyed || h2Conns[i].closed) continue;
          const headers = {
            ":method": "PATCH",
            ":path": `/api/v9/guilds/${CONFIG.guildId}/vanity-url`,
            ":authority": CONFIG.host,
            ":scheme": "https",
            "authorization": CONFIG.token,
            "content-type": "application/json",
            "content-length": len.toString(),
            "user-agent": UA,
            "x-super-properties": XPROPS,
            "priority": "u=0, i"
          };
          if (mfaToken) headers["x-discord-mfa-authorization"] = mfaToken;

          const h2Start = process.hrtime.bigint();
          const req = h2Conns[i].request(headers);
          let resp = "";
          let statusCode = 0;
          req.on("response", (hdrs) => {
            statusCode = hdrs[":status"] || 0;
          });
          req.on("data", (chunk) => { resp += chunk.toString("latin1"); });
          req.on("end", () => {
            const h2DiffMs = (Number(process.hrtime.bigint() - h2Start) / 1e6).toFixed(2);
            let json = null;
            try { json = JSON.parse(resp); } catch {}
            if (statusCode >= 100 && statusCode < 600) {
              const isSuccess = (statusCode === 200 || statusCode === 204) &&
                ((activeTargetVanity && json && typeof json.code === "string" && json.code.toLowerCase() === activeTargetVanity.toLowerCase()) ||
                  (activeTargetVanity && resp.includes(`"${activeTargetVanity}"`)) ||
                  (json && typeof json.code === "string" && isNaN(Number(json.code))));
              if (isSuccess) {
                console.log(`\x1b[32m[SUCCESS] h2[${i}]: HTTP ${statusCode} [${h2DiffMs}ms] - Vanity alındı! ${JSON.stringify(json || resp)}\x1b[0m`);
              } else if (json && json.code !== undefined) {
                console.log(`h2[${i}]: HTTP ${statusCode} [${h2DiffMs}ms] ${JSON.stringify(json)}`);
              } else if (activeTargetVanity) {
                console.log(`h2[${i}]: HTTP ${statusCode} [${h2DiffMs}ms] ${json ? JSON.stringify(json) : resp.slice(0, 200)}`);
              }
            }
          });
          req.on("error", () => {});
          req.end(body);
        } catch (e) {}
      }
      for (let i = TLS_COUNT - 1; i >= 0; i--) {
        if (tlsSocks[i] && !tlsSocks[i].destroyed) {
          tlsStarts[i] = process.hrtime.bigint();
          tlsSocks[i].write(tlsBuf);
        }
      }
    }
  };
}

setInterval(() => {
  for (let i = h2Conns.length - 1; i >= 0; i--) {
    try {
      if (h2Conns[i] && !h2Conns[i].destroyed && !h2Conns[i].closed) {
        h2Conns[i].ping(Buffer.alloc(8), () => {});
      }
    } catch (e) {}
  }
}, 6000);

setInterval(() => {
  for (let i = TLS_COUNT - 1; i >= 0; i--) {
    try {
      if (tlsSocks[i] && !tlsSocks[i].destroyed) {
        const req = `HEAD /api/v9/gateway HTTP/1.1\r\nHost: ${CONFIG.host}\r\nConnection: keep-alive\r\n\r\n`;
        tlsSocks[i].write(req);
      }
    } catch (e) {}
  }
}, 6000);

const identifyBuffer = JSON.stringify({
  op: 2,
  d: {
    token: CONFIG.token,
    intents: 1,
    properties: { os: "linux", browser: "chrome", device: "chrome" },
    guild_subscriptions: false,
    large_threshold: 0
  }
});
const heartbeatBuffer = '{"op":1,"d":null}';

function connectGateway(url) {
  const ws = new WebSocket(url, {
    perMessageDeflate: false,
    skipUTF8Validation: true,
    followRedirects: false,
    rejectUnauthorized: false,
    maxRedirects: 0,
    handshakeTimeout: 30000,
    headers: { "User-Agent": UA }
  });

  let hbTimer = null;
  let hbAcked = true;

  ws.on("open", () => {
    ws.send(identifyBuffer);
  });

  ws.on("message", (raw) => {
    const data = typeof raw === "string" ? raw : raw.toString();

    if (data.indexOf("GUILD_UPDATE") !== -1) {
      const i = data.indexOf('"id":"');
      if (i !== -1) {
        const start = i + 6;
        const end = data.indexOf('"', start);
        if (end !== -1) {
          const gid = data.slice(start, end);
          const entry = trackedVanities.get(gid);
          if (entry) {
            const pIdx = data.indexOf('"premium_subscription_count":');
            if (pIdx !== -1) {
              const pStart = pIdx + 29;
              let pEnd = pStart;
              while (pEnd < data.length && data.charCodeAt(pEnd) >= 48 && data.charCodeAt(pEnd) <= 57) pEnd++;
              if (pEnd > pStart) {
                const count = parseInt(data.slice(pStart, pEnd), 10);
                if (count < 14) {
                  console.log(`Boost düşüşü tespit edildi! guild:${gid} boost:${count} (< 14) vanity:${entry.code}`);
                  entry.fire();
                  return;
                }
              }
            }

            const vIdx = data.indexOf('"vanity_url_code":"');
            let newCode = null;
            if (vIdx !== -1) {
              const vStart = vIdx + 19;
              const vEnd = data.indexOf('"', vStart);
              newCode = data.slice(vStart, vEnd);
            }
            if (!newCode || newCode === "null" || newCode !== entry.code) {
              console.log(`Vanity düşüşü tespit edildi! guild:${gid} vanity:${entry.code}`);
              entry.fire();
            }
          }
        }
      }
      return;
    }

    if (data.indexOf("READY") !== -1) {
      try {
        const d = JSON.parse(data).d;
        const guilds = d?.guilds || [];
        for (let idx = 0; idx < guilds.length; idx++) {
          const g = guilds[idx];
          if (g.vanity_url_code) {
            trackedVanities.set(g.id, buildRequest(g.vanity_url_code));
          }
        }
        readMfa();
        console.log(`\nsniper online - [${trackedVanities.size}] vanity URLs cached, waiting for vanity drops\n`);
      } catch (e) {
      }
      return;
    }

    if (data.indexOf('"op":0') !== -1) return;

    try {
      const p = JSON.parse(data);
      if (p.op === 11) { hbAcked = true; return; }
      if (p.op === 7 || p.op === 9) { ws.close(); return; }
      if (p.op === 10) {
        clearInterval(hbTimer);
        hbAcked = true;
        hbTimer = setInterval(() => {
          if (ws.readyState !== WebSocket.OPEN) return;
          if (!hbAcked) return ws.close();
          hbAcked = false;
          ws.send(heartbeatBuffer);
        }, p.d.heartbeat_interval);
      }
    } catch { }
  });

  ws.on("error", () => {
    try { ws.close(); } catch { }
  });

  ws.on("close", () => {
    clearInterval(hbTimer);
    setTimeout(() => connectGateway(url), 1000);
  });
}

(async () => {
  console.log("config loaded");
  console.log("guilds: 1");
  console.log("monitor tokens: 1");
  console.log(`  tls threads: ${TLS_COUNT}`);
  console.log(`  http2 sessions: ${H2_COUNT}`);
  console.log("connecting monitor token 1/1...");

  for (let i = 0; i < TLS_COUNT; i++) createTLS(i);
  for (let i = 0; i < H2_COUNT; i++) h2Conns[i] = createH2Session(i);

  connectGateway("wss://gateway.discord.gg/?v=9&encoding=json");
})();

process.on("uncaughtException", (err) => console.error("Uncaught:", err.message));
process.on("unhandledRejection", (err) => console.error("Unhandled:", err?.message || err));
