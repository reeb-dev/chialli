import { createHmac, timingSafeEqual } from "node:crypto";

// Postgres por HTTP (mismo protocolo que @neondatabase/serverless), sin dependencias.
const DB = process.env.DATABASE_URL;
const SQL_URL = process.env.SQL_URL || "https://" + new URL(DB || "postgres://x@x.x/x").hostname.replace(/^[^.]+\./, "api.") + "/sql";
async function run(body) {
  const r = await fetch(SQL_URL, { method: "POST", headers: { "Neon-Connection-String": DB, "Neon-Raw-Text-Output": "true", "Neon-Array-Mode": "true", "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const d = await r.json(); if (!r.ok) throw new Error(d.message || "sql " + r.status); return d;
}
const toRows = res => res.rows.map(r => Object.fromEntries(res.fields.map((f, i) => [f.name, r[i]])));
const q = async (query, params = []) => { const d = await run({ query, params }); return { rows: toRows(d), rowCount: d.rowCount }; };
const tx = queries => run({ queries });
const SECRET = process.env.TOKEN_SECRET;
const DIAS = 180;
const COLS = new Set(["ingredientes", "recetas", "proveedores", "historial", "config"]);
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Max-Age": "86400" };
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...CORS, "Content-Type": "application/json" } });
const b64 = s => Buffer.from(s).toString("base64url");
const firma = s => createHmac("sha256", SECRET).update(s).digest("base64url");
function token(email) { const p = b64(JSON.stringify({ e: email, x: Date.now() + DIAS * 864e5 })); return p + "." + firma(p); }
function leer(req) {
  const t = (req.headers.get("authorization") || "").replace(/^Bearer /, ""); const [p, f] = t.split(".");
  if (!p || !f) return null; const ok = Buffer.from(firma(p)); const got = Buffer.from(f);
  if (ok.length !== got.length || !timingSafeEqual(ok, got)) return null;
  try { const d = JSON.parse(Buffer.from(p, "base64url").toString()); return d.x > Date.now() ? d.e : null; } catch { return null; }
}
const limpio = e => String(e || "").trim().toLowerCase();
const intentos = new Map();
function frenar(k) { const n = Date.now(), a = (intentos.get(k) || []).filter(t => n - t < 6e5); a.push(n); intentos.set(k, a); return a.length > 10; }

export default {
  async fetch(req) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (!SECRET) return json({ error: "Falta configurar el servidor" }, 500);
    const path = new URL(req.url).pathname.replace(/\/+$/, "") || "/";
    try {
      if (path === "/" && req.method === "GET") {
        const { rows } = await q("select count(*) n from usuarios");
        return json({ ok: true, hayUsuarios: +rows[0].n > 0 });
      }
      const body = req.method === "POST" ? await req.json().catch(() => ({})) : {};
      if (path === "/registro" || path === "/login") {
        const email = limpio(body.email), clave = String(body.clave || "");
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || clave.length < 8) return json({ error: "Revisá el email y que la contraseña tenga al menos 8 caracteres." }, 400);
        if (frenar(email)) return json({ error: "Demasiados intentos. Esperá unos minutos." }, 429);
        if (path === "/registro") {
          if (!process.env.SETUP_CODE || String(body.codigo || "").trim().toUpperCase() !== process.env.SETUP_CODE) return json({ error: "El código de activación no es correcto." }, 403);
          const { rowCount } = await q("insert into usuarios (email, clave, dueno) select $1, crypt($2, gen_salt('bf')), true where not exists (select 1 from usuarios)", [email, clave]);
          if (!rowCount) return json({ error: "El panel ya tiene dueña o dueño. Pedile que te agregue." }, 403);
          return json({ token: token(email), email, dueno: true });
        }
        const { rows } = await q("select dueno from usuarios where email = $1 and clave = crypt($2, clave)", [email, clave]);
        if (!rows.length) return json({ error: "Email o contraseña incorrectos." }, 401);
        intentos.delete(email);
        return json({ token: token(email), email, dueno: rows[0].dueno === "t" });
      }
      const email = leer(req);
      const yo = email && (await q("select email, dueno = true as dueno from usuarios where email = $1", [email])).rows[0];
      if (yo) yo.dueno = yo.dueno === "t";
      if (!yo) return json({ error: "Tenés que volver a ingresar." }, 401);
      if (path === "/datos" && req.method === "GET") {
        const { rows } = await q("select coalesce(json_agg(json_build_object('col', col, 'id', id, 'data', data) order by col, id), '[]')::text j from docs");
        return json({ docs: JSON.parse(rows[0].j), email: yo.email, dueno: yo.dueno });
      }
      if (path === "/guardar" && req.method === "POST") {
        const ops = Array.isArray(body.ops) ? body.ops.slice(0, 500) : [];
        if (!ops.every(o => COLS.has(o.col) && typeof o.id === "string" && o.id.length <= 80 && (o.op === "del" || (o.op === "put" && o.data && typeof o.data === "object"))))
          return json({ error: "Datos inválidos" }, 400);
        await tx([
          ...ops.map(o => o.op === "put"
            ? { query: "insert into docs (col, id, data) values ($1, $2, $3) on conflict (col, id) do update set data = excluded.data, actualizado = now()", params: [o.col, o.id, JSON.stringify(o.data)] }
            : { query: "delete from docs where col = $1 and id = $2", params: [o.col, o.id] }),
          { query: "delete from docs where col = 'historial' and id not in (select id from docs where col = 'historial' order by (data->>'fecha') desc nulls last limit 150)", params: [] },
        ]);
        return json({ ok: true });
      }
      if (path === "/usuarios") {
        if (!yo.dueno) return json({ error: "Solo la dueña o el dueño puede manejar usuarios." }, 403);
        if (req.method === "POST") {
          const em = limpio(body.email), clave = String(body.clave || "");
          if (body.borrar) { if (em === yo.email) return json({ error: "No podés borrarte a vos." }, 400); await q("delete from usuarios where email = $1 and not dueno", [em]); }
          else {
            if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em) || clave.length < 8) return json({ error: "Revisá el email y que la contraseña tenga al menos 8 caracteres." }, 400);
            await q("insert into usuarios (email, clave) values ($1, crypt($2, gen_salt('bf'))) on conflict (email) do update set clave = excluded.clave", [em, clave]);
          }
        }
        const { rows } = await q("select email, dueno from usuarios order by dueno desc, email");
        return json({ usuarios: rows.map(r => ({ email: r.email, dueno: r.dueno === "t" })) });
      }
      return json({ error: "No encontrado" }, 404);
    } catch (e) { console.error(e); return json({ error: "Error del servidor" }, 500); }
  },
};
