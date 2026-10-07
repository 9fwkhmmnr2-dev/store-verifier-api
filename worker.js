export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = env.ALLOWED_ORIGIN || "*";
    const cors = {
      "Access-Control-Allow-Origin": allowed === "*" ? "*" : allowed,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Content-Type": "application/json; charset=utf-8",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    const reply = (obj, status = 200) =>
      new Response(JSON.stringify(obj), { status, headers: cors });

    if (allowed !== "*" && origin && origin !== allowed) {
      return reply({ error: "Origen no permitido" }, 403);
    }

    const domain = normalizeDomain(new URL(request.url).searchParams.get("domain"));
    if (!domain) return reply({ error: "Dominio inválido" }, 400);

    const [registro, pagina, seguridad] = await Promise.all([
      getRegistro(domain),
      getPagina(domain),
      getSafeBrowsing(domain, env),
    ]);
    return reply({ domain, registro, pagina, seguridad, generado: new Date().toISOString() });
  },
};

function normalizeDomain(raw) {
  if (!raw) return null;
  const h = raw.trim().toLowerCase().replace(/^https?:\/\//, "")
    .split(/[\/?#]/)[0].replace(/^www\./, "");
  if (h.length > 100 || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(h)) return null;
  if (/^\d+(\.\d+)+$/.test(h)) return null;
  if (/\.(local|internal|localhost|lan)$/.test(h)) return null;
  return h;
}

async function getRegistro(d) {
  try {
    const base = d.endsWith(".ar") ? "https://rdap.nic.ar/domain/" : "https://rdap.org/domain/";
    const r = await fetch(base + d, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(6000),
    });
    if (!r.ok) return { ok: false };
    const j = await r.json();
    const ev = (j.events || []).find((e) => e.eventAction === "registration");
    if (!ev) return { ok: false };
    const f = new Date(ev.eventDate);
    if (isNaN(f)) return { ok: false };
    return { ok: true, fecha: f.toISOString(), dias: Math.floor((Date.now() - f) / 864e5) };
  } catch {
    return { ok: false };
  }
}

function cuitValido(c) {
  c = c.replace(/\D/g, "");
  if (c.length !== 11) return false;
  const m = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  let s = 0;
  for (let i = 0; i < 10; i++) s += parseInt(c[i], 10) * m[i];
  let v = 11 - (s % 11);
  if (v === 11) v = 0;
  if (v === 10) v = 9;
  return v === parseInt(c[10], 10);
}

async function getPagina(d) {
  try {
    const r = await fetch("https://" + d, {
      headers: {
        "User-Agent": "StoreVerifierBot/1.0 (verificador de tiendas online)",
        Accept: "text/html",
      },
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
    });
    const tipo = r.headers.get("content-type") || "";
    const largo = parseInt(r.headers.get("content-length") || "0", 10);
    if (!r.ok || !tipo.includes("text/html") || largo > 5_000_000) {
      return { ok: false, status: r.status };
    }
    const html = (await r.text()).slice(0, 600000);
    const low = html.toLowerCase();
    const txt = low
      .replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/g, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ");
    const has = (re) => re.test(txt);

    const cuits = [...new Set(
      (txt.match(/\b(?:20|23|24|27|30|33|34)[-\s]?\d{8}[-\s]?\d\b/g) || [])
        .map((c) => c.replace(/\D/g, ""))
    )].slice(0, 5).map((c) => ({ cuit: c, valido: cuitValido(c) }));

    const redes = [...new Set(
      (low.match(/(?:instagram|facebook|tiktok)\.com\/[a-z0-9_.\-]+/g) || [])
    )].slice(0, 6);

    let plataforma = "desconocida";
    if (/tiendanube|nuvemshop/.test(low)) plataforma = "Tiendanube";
    else if (/cdn\.shopify|shopify/.test(low)) plataforma = "Shopify";
    else if (/woocommerce|wp-content/.test(low)) plataforma = "WooCommerce";
    else if (/vtex/.test(low)) plataforma = "VTEX";

    return {
      ok: true,
      hostFinal: new URL(r.url).hostname,
      titulo: (html.match(/<title[^>]*>([^<]{0,120})/i) || [, ""])[1].trim(),
      cuits,
      pagos: {
        mercadopago: has(/mercado\s?pago/),
        tarjeta: has(/tarjeta|visa|mastercard|cuotas/),
        transferencia: has(/transferencia|\bcbu\b|\balias\b/),
        cripto: has(/bitcoin|usdt|cripto/),
      },
      politicas: {
        cambios_devoluciones: has(/pol[ií]tica[s]? de (cambios?|devoluci)|cambios y devoluciones/),
        arrepentimiento: has(/arrepentimiento/),
        defensa_consumidor: has(/defensa del consumidor|defensa\s?consumidor/),
      },
      contacto: {
        whatsapp: /wa\.me|api\.whatsapp\.com/.test(low),
        email: /mailto:/.test(low),
        domicilio: has(/domicilio|direcci[oó]n/),
      },
      redes,
      plataforma,
    };
  } catch {
    return { ok: false };
  }
}

async function getSafeBrowsing(d, env) {
  if (!env.SAFE_BROWSING_KEY) return { ok: false, motivo: "sin_clave" };
  try {
    const r = await fetch(
      "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + env.SAFE_BROWSING_KEY,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "store-verifier", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: "https://" + d + "/" }, { url: "http://" + d + "/" }],
          },
        }),
        signal: AbortSignal.timeout(6000),
      }
    );
    if (!r.ok) return { ok: false };
    const j = await r.json();
    return { ok: true, amenazas: (j.matches || []).map((m) => m.threatType) };
  } catch {
    return { ok: false };
  }
}
