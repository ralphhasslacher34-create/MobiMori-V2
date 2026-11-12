/*
 * MobiMory Konto-Dienst (Schritt 13a seit 2.0.64, Abgleich und Sicherung 13b seit 2.0.65)
 *
 * Ein Cloudflare-Worker mit D1-Datenbank. Er kann:
 *   - Konto anlegen mit E-Mail + Passwort (die Adresse wird per Code bestätigt)
 *   - Anmelden mit E-Mail + Passwort
 *   - Anmelden mit E-Mail + Code (ohne Passwort; legt bei der ersten Anmeldung das Konto an)
 *   - Passwort setzen oder ändern, abmelden, Konto löschen
 * Jeder Nutzer bekommt beim ersten Bestätigen einen eigenen Datenraum.
 *
 * Alles liegt in dieser einen Datei, damit man sie im Cloudflare-Dashboard einfügen kann.
 * Die Einrichtung steht in server/EINRICHTUNG.md. Die Tabellen stehen in server/schema.sql.
 *
 * Nötig im Worker (siehe EINRICHTUNG.md):
 *   Bindung  DB                    die D1-Datenbank (Jurisdiktion EU, nur beim Anlegen einstellbar)
 *   Geheimnis PASSWORT_PEPPER       mindestens 32 zufällige Zeichen; geht es verloren, passt kein Passwort mehr
 *   Variable ERLAUBTE_URSPRUENGE    Adresse(n) der App, durch Komma getrennt, ohne Pfad
 * Für den echten Dienst zusätzlich:
 *   Bindung  EMAIL + Variable ABSENDER   Cloudflare Email Service (eigene Domain nötig)
 * Nur für einen Test-Dienst mit eigener Test-Datenbank:
 *   Variable ENTWICKLUNG = 1       der Code wird in der Antwort mitgeschickt statt per E-Mail.
 *                                  NIEMALS im echten Dienst setzen.
 *
 * 13b: Abgleich zwischen Geräten (nur die festgelegten Datenarten, ohne lokale Angaben wie Notizen) und verschlüsselte Sicherung
 *      (der Dienst speichert nur Bytes, die er nicht lesen kann). Dafür sind sechs weitere Tabellen nötig (schema.sql, ab „13b“).
 * 13d: Dateien (Fotos, Scans, Dokumente) liegen in Cloudflare R2 (Bindung DATEN, Jurisdiktion EU), die Angaben dazu stehen im Abgleich. Scans von
 *      Nachweisen kommen mit dem Schlüsselwort des Nutzers verschlüsselt an, der Dienst sieht nur Bytes. Eine weitere Tabelle „datei“ (schema.sql, ab „13d“).
 * 13c: Freigaben je Fahrzeug und Zeitraum (nur lesen, höchstens 12 Monate, Einladung per Code an die E-Mail-Adresse des Gastes) und die Kontroll-Freigabe
 *      per Code (ohne Konto, nur Papiere und Prüfergebnis, höchstens 7 Tage). Die Rechte werden bei jeder Anfrage auf dem Server geprüft. Zwei weitere
 *      Tabellen „freigabe“ und „kontrolle“ (schema.sql, ab „13c“).
 * 13e: Stufen (Basic, Testwoche, Mittel, Voll, Entwickler ohne Grenzen) mit Grenzen für Geräte und Online-Checks. Die Online-Checks gehen über diesen Dienst: Er prüft Anmeldung,
 *      Stufe und Kontingent, zählt, reicht die Anfrage an den Recherche-Dienst weiter und speichert das Ergebnis (Check-Datenbank). Eine Testwoche je
 *      bestätigter E-Mail-Adresse. Vier weitere Tabellen (schema.sql, ab „13e“). Nötig dafür: Variable RECHERCHE_URL und Geheimnis RECHERCHE_TOKEN.
 * 13e-3 (seit 2.0.71): Kosten-Wächter. Alle 15 Minuten (Cron-Auslöser in wrangler-konto.jsonc) prüft der Dienst, ob die Kosten der Testwochen im Verhältnis
 *      zu den Einnahmen zu hoch werden oder ob zu viele neue Testwochen entstehen, und schickt dann höchstens eine Mail pro Stunde (nur Zahlen, keine Namen).
 *      Eine weitere Tabelle „waechter_stand“ (schema.sql, 13e-3.sql). Nötig dafür: Variable WAECHTER_EMAIL (Empfänger). Alle Schwellen und Preise sind
 *      Variablen mit Standardwerten (siehe „Kosten-Wächter“ weiter unten).
 */

export const DIENST = 'mobimory-konto';
export const VERSION = '13e-3';

/* Die Laufzeit von Cloudflare lehnt mehr als 100 000 Runden ab. Die Zahl steht im gespeicherten Wert, sie lässt sich später erhöhen. */
export const PBKDF2_RUNDEN = 100000;
const SITZUNG_TAGE = 90;
const SITZUNG_ERNEUERN_TAGE = 30;
const CODE_MINUTEN = 10;
const CODE_VERSUCHE = 5;
const MAX_BODY = 4096;
const MIN_PASSWORT = 10;
const MAX_PASSWORT_BYTES = 200;
const MAX_ABGLEICH_BODY = 2 * 1024 * 1024;
const MAX_ABGLEICH_NUTZLAST = 256 * 1024;
const MAX_PAKET = 40;
const MAX_DATEI_BYTES = 20 * 1024 * 1024;
const MAX_KONTO_DATEI_BYTES = 1024 * 1024 * 1024;
const DATEI_SEITE = 500;
const HOL_SEITE = 60;
const TEIL_BYTES = 256 * 1024;
const MAX_SICHERUNG_BYTES = 8 * 1024 * 1024;
const MAX_BASE64_TEIL = Math.ceil(TEIL_BYTES / 3) * 4;
const SICHERUNGEN_BEHALTEN = 2;
const MINUTE = 60 * 1000;
const TAG = 24 * 60 * MINUTE;

const kodieren = new TextEncoder();

class HttpFehler extends Error {
  constructor(status, text, extra) { super(text); this.status = status; this.extra = extra || {}; }
}

/* ---------- kleine Werkzeuge ---------- */

function zuBase64Url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function ausBase64Url(text) {
  const b = atob(String(text).replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}

function zuHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function zufall(n) { return crypto.getRandomValues(new Uint8Array(n)); }

async function sha256Hex(text) {
  return zuHex(new Uint8Array(await crypto.subtle.digest('SHA-256', kodieren.encode(text))));
}

async function hmac(geheimnis, text) {
  const key = await crypto.subtle.importKey('raw', kodieren.encode(geheimnis), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, kodieren.encode(text)));
}

/* Vergleich ohne Abkürzung bei der ersten Abweichung. */
function gleich(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

/* Sechs Ziffern, gleichmäßig verteilt (Werte oberhalb der Grenze werden verworfen). */
function sechsZiffern() {
  const grenze = Math.floor(0x100000000 / 1000000) * 1000000;
  for (;;) {
    const z = crypto.getRandomValues(new Uint32Array(1))[0];
    if (z < grenze) return String(z % 1000000).padStart(6, '0');
  }
}

function pepper(env) {
  const p = env && env.PASSWORT_PEPPER;
  if (typeof p !== 'string' || p.length < 32) {
    throw new HttpFehler(503, 'Der Dienst ist noch nicht fertig eingerichtet: Das Geheimnis PASSWORT_PEPPER fehlt oder ist zu kurz.');
  }
  return p;
}

function datenbank(env) {
  if (!env || !env.DB) throw new HttpFehler(503, 'Der Dienst ist noch nicht fertig eingerichtet: Die Datenbank (Bindung DB) fehlt.');
  return env.DB;
}

/* ---------- Passwort ---------- */

async function ableiten(passwort, salt, runden, geheimnis) {
  const vor = await hmac(geheimnis, passwort);
  const key = await crypto.subtle.importKey('raw', vor, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: runden }, key, 256));
}

export async function passwortHashen(passwort, geheimnis) {
  const salt = zufall(16);
  const h = await ableiten(passwort, salt, PBKDF2_RUNDEN, geheimnis);
  return 'pbkdf2-sha256-hmac$' + PBKDF2_RUNDEN + '$' + zuBase64Url(salt) + '$' + zuBase64Url(h);
}

/* Liefert { ok, veraltet }. „veraltet“ heißt: richtig, aber mit weniger Runden gespeichert als heute. */
export async function passwortPruefen(passwort, gespeichert, geheimnis) {
  const t = String(gespeichert || '').split('$');
  if (t.length !== 4 || t[0] !== 'pbkdf2-sha256-hmac') return { ok: false, veraltet: false };
  const runden = parseInt(t[1], 10);
  if (!(runden >= 1000 && runden <= 100000)) return { ok: false, veraltet: false };
  let salt, soll;
  try { salt = ausBase64Url(t[2]); soll = ausBase64Url(t[3]); } catch (e) { return { ok: false, veraltet: false }; }
  const ist = await ableiten(passwort, salt, runden, geheimnis);
  return { ok: gleich(ist, soll), veraltet: runden < PBKDF2_RUNDEN };
}

/* Gleiche Rechenzeit für unbekannte Adressen, damit man an der Antwortzeit nicht erkennt, ob es ein Konto gibt. */
async function blindPruefen(passwort, geheimnis) {
  await ableiten(passwort, new Uint8Array(16), PBKDF2_RUNDEN, geheimnis);
}

/* ---------- Eingaben prüfen ---------- */

function emailNormal(roh) {
  const t = typeof roh === 'string' ? roh.trim().toLowerCase() : '';
  if (!t || t.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(t)) {
    throw new HttpFehler(400, 'Die E-Mail-Adresse ist ungültig.', { feld: 'email' });
  }
  return t;
}

function passwortRegeln(p) {
  if (typeof p !== 'string' || p.length < MIN_PASSWORT) {
    throw new HttpFehler(400, 'Das Passwort ist zu kurz. Es braucht mindestens ' + MIN_PASSWORT + ' Zeichen.', { feld: 'passwort' });
  }
  if (kodieren.encode(p).length > MAX_PASSWORT_BYTES) {
    throw new HttpFehler(400, 'Das Passwort ist zu lang.', { feld: 'passwort' });
  }
  return p;
}

async function bodyLesen(request, max) {
  const text = await request.text();
  if (text.length > (max || MAX_BODY)) throw new HttpFehler(413, 'Die Anfrage ist zu groß.');
  if (!text) return {};
  try {
    const j = JSON.parse(text);
    if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('kein Objekt');
    return j;
  } catch (e) { throw new HttpFehler(400, 'Die Anfrage ist kein gültiges JSON.'); }
}

/* ---------- Bremse gegen Durchprobieren ---------- */

async function bremsen(db, schluessel, max, fensterMs, jetzt, text) {
  const z = await db.prepare('SELECT anzahl, fenster_bis FROM drossel WHERE schluessel = ?').bind(schluessel).first();
  if (!z || z.fenster_bis <= jetzt) {
    await db.prepare('INSERT INTO drossel (schluessel, anzahl, fenster_bis) VALUES (?, 1, ?) ON CONFLICT(schluessel) DO UPDATE SET anzahl = 1, fenster_bis = excluded.fenster_bis')
      .bind(schluessel, jetzt + fensterMs).run();
    return;
  }
  if (z.anzahl >= max) {
    const sek = Math.ceil((z.fenster_bis - jetzt) / 1000);
    throw new HttpFehler(429, text + ' Bitte warte etwa ' + Math.max(1, Math.ceil(sek / 60)) + ' Minute(n).', { wartenSekunden: sek });
  }
  await db.prepare('UPDATE drossel SET anzahl = anzahl + 1 WHERE schluessel = ?').bind(schluessel).run();
}

async function schluesselFuer(praefix, wert) {
  return praefix + ':' + (await sha256Hex(wert)).slice(0, 32);
}

async function aufraeumen(db, jetzt) {
  await db.batch([
    db.prepare('DELETE FROM drossel WHERE fenster_bis <= ?').bind(jetzt),
    db.prepare('DELETE FROM sitzung WHERE laeuft_ab <= ?').bind(jetzt),
    db.prepare('DELETE FROM code WHERE laeuft_ab <= ?').bind(jetzt),
    /* Adressen, die nie bestätigt wurden, verschwinden nach sieben Tagen. */
    db.prepare('DELETE FROM nutzer WHERE bestaetigt_am IS NULL AND erstellt_am <= ?').bind(jetzt - 7 * TAG)
  ]);
  await freigabenAufraeumen(db, jetzt);
  await checksAufraeumen(db, jetzt);
}

/* ---------- E-Mail ---------- */

function htmlSauber(t) { return String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

async function mailSenden(env, an, betreff, text) {
  if (env.EMAIL && env.ABSENDER) {
    try {
      await env.EMAIL.send({ to: an, from: env.ABSENDER, subject: betreff, text, html: '<p>' + htmlSauber(text).replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>') + '</p>' });
    } catch (e) {
      throw new HttpFehler(502, 'Die E-Mail konnte nicht gesendet werden. Bitte später noch einmal versuchen.');
    }
    return { gesendet: true };
  }
  if (env.ENTWICKLUNG === '1') return { gesendet: false, entwicklung: true };
  throw new HttpFehler(503, 'Der Dienst kann noch keine E-Mails senden: Der Versand ist nicht eingerichtet.');
}

/* Legt einen neuen Code an (ein alter für dieselbe Adresse verfällt) und schickt ihn. */
async function codeSenden(env, db, email, zweck, jetzt) {
  const code = sechsZiffern();
  const hash = zuHex(await hmac(pepper(env), email + ':' + code));
  await db.prepare('INSERT INTO code (email, zweck, code_hash, laeuft_ab, versuche) VALUES (?, ?, ?, ?, 0) ON CONFLICT(email) DO UPDATE SET zweck = excluded.zweck, code_hash = excluded.code_hash, laeuft_ab = excluded.laeuft_ab, versuche = 0')
    .bind(email, zweck, hash, jetzt + CODE_MINUTEN * MINUTE).run();
  let r;
  try {
    r = await mailSenden(env, email, 'Dein MobiMory-Code: ' + code,
      'Dein Code für MobiMory lautet ' + code + '.\n\nEr gilt ' + CODE_MINUTEN + ' Minuten und nur einmal.\n\nWenn du ihn nicht angefordert hast, ignoriere diese E-Mail. Es passiert nichts.');
  } catch (e) {
    await db.prepare('DELETE FROM code WHERE email = ?').bind(email).run();
    throw e;
  }
  return r.entwicklung ? code : null;
}

/* ---------- Sitzung ---------- */

async function sitzungAnlegen(db, nutzerId, geraet, jetzt) {
  /* 13e: Die App hängt eine Kennung des Geräts an den Namen („… #ab12cd34“). Meldet sich dasselbe Gerät noch einmal an, ersetzt die neue Sitzung die alte.
     Der Name allein genügt nicht, er ist bei allen Geräten gleich. Danach gilt die Geräte-Grenze der Stufe. */
  const km = /#([a-f0-9]{8,16})$/.exec(geraet || '');
  if (km) await db.prepare('DELETE FROM sitzung WHERE nutzer_id = ? AND geraet LIKE ?').bind(nutzerId, '%#' + km[1]).run();
  const st = await stufeVon(db, nutzerId, jetzt, true);
  if (st && st.grenzen) {
    const z = await db.prepare('SELECT COUNT(*) AS n FROM sitzung WHERE nutzer_id = ? AND laeuft_ab > ?').bind(nutzerId, jetzt).first();
    if (z && st.grenzen.geraete !== null && z.n >= st.grenzen.geraete) {
      throw new HttpFehler(403, 'Mit der Stufe ' + st.name + ' sind höchstens ' + st.grenzen.geraete + ' Geräte erlaubt. Melde zuerst ein anderes Gerät ab.', { stufe: st.id, geraeteGrenze: st.grenzen.geraete });
    }
  }
  const token = zuBase64Url(zufall(32));
  const laeuftAb = jetzt + SITZUNG_TAGE * TAG;
  await db.prepare('INSERT INTO sitzung (token_hash, nutzer_id, erstellt_am, laeuft_ab, geraet) VALUES (?, ?, ?, ?, ?)')
    .bind(await sha256Hex(token), nutzerId, jetzt, laeuftAb, geraet || null).run();
  return { token, laeuftAb };
}

function geraetName(roh) { return typeof roh === 'string' ? roh.trim().slice(0, 60) : ''; }

async function sitzungAnwort(db, nutzerId, geraet, jetzt) {
  const n = await db.prepare('SELECT n.email AS email, n.passwort_hash AS passwort_hash, d.id AS dr_id, d.name AS dr_name FROM nutzer n LEFT JOIN datenraum d ON d.nutzer_id = n.id WHERE n.id = ?').bind(nutzerId).first();
  const s = await sitzungAnlegen(db, nutzerId, geraet, jetzt);
  return { ok: true, token: s.token, laeuftAb: s.laeuftAb, email: n.email, datenraum: { id: n.dr_id, name: n.dr_name }, passwortGesetzt: !!n.passwort_hash };
}

async function authentifizieren(request, db, jetzt) {
  const kopf = request.headers.get('Authorization') || '';
  const m = /^Bearer\s+([A-Za-z0-9_-]{20,100})$/.exec(kopf);
  if (!m) throw new HttpFehler(401, 'Du bist nicht angemeldet.');
  const hash = await sha256Hex(m[1]);
  const z = await db.prepare('SELECT s.laeuft_ab AS laeuft_ab, n.id AS id, n.email AS email, n.passwort_hash AS passwort_hash, d.id AS dr_id FROM sitzung s JOIN nutzer n ON n.id = s.nutzer_id LEFT JOIN datenraum d ON d.nutzer_id = n.id WHERE s.token_hash = ? AND s.laeuft_ab > ?').bind(hash, jetzt).first();
  if (!z) throw new HttpFehler(401, 'Die Anmeldung ist abgelaufen. Bitte melde dich neu an.');
  let laeuftAb = z.laeuft_ab;
  if (laeuftAb - jetzt < SITZUNG_ERNEUERN_TAGE * TAG) {
    laeuftAb = jetzt + SITZUNG_TAGE * TAG;
    await db.prepare('UPDATE sitzung SET laeuft_ab = ? WHERE token_hash = ?').bind(laeuftAb, hash).run();
  }
  return { id: z.id, email: z.email, passwortGesetzt: !!z.passwort_hash, hash, laeuftAb, datenraumId: z.dr_id || null };
}

/* ---------- die Wege ---------- */

const ANTWORT_CODE = { ok: true, codeGesendet: true, gueltigMinuten: CODE_MINUTEN };

async function registrieren(request, env, db, jetzt) {
  const b = await bodyLesen(request);
  const email = emailNormal(b.email);
  const pw = passwortRegeln(b.passwort);
  const ip = request.headers.get('CF-Connecting-IP') || 'unbekannt';
  await bremsen(db, await schluesselFuer('cod-e', email), 5, 60 * MINUTE, jetzt, 'Für diese Adresse wurden zu viele Codes angefordert.');
  await bremsen(db, await schluesselFuer('cod-i', ip), 20, 60 * MINUTE, jetzt, 'Von hier wurden zu viele Codes angefordert.');
  const g = pepper(env);
  const n = await db.prepare('SELECT id, bestaetigt_am FROM nutzer WHERE email = ?').bind(email).first();
  let zweck = 'anmelden';
  if (!n || !n.bestaetigt_am) {
    /* Das Passwort wird erst wirksam, wenn der Code aus der E-Mail stimmt. So kann niemand ein fremdes Konto vorbelegen. */
    const hash = await passwortHashen(pw, g);
    if (!n) await db.prepare('INSERT INTO nutzer (id, email, passwort_wartend, erstellt_am) VALUES (?, ?, ?, ?)').bind(crypto.randomUUID(), email, hash, jetzt).run();
    else await db.prepare('UPDATE nutzer SET passwort_wartend = ? WHERE id = ?').bind(hash, n.id).run();
    zweck = 'registrieren';
  } else {
    await blindPruefen(pw, g);
  }
  /* Gleiche Antwort, ob die Adresse neu ist oder nicht. Ein bestätigtes Konto bekommt einen Anmelde-Code. */
  const dev = await codeSenden(env, db, email, zweck, jetzt);
  return Object.assign({}, ANTWORT_CODE, dev ? { entwicklungsCode: dev } : {});
}

async function codeAnfordern(request, env, db, jetzt) {
  const b = await bodyLesen(request);
  const email = emailNormal(b.email);
  const ip = request.headers.get('CF-Connecting-IP') || 'unbekannt';
  await bremsen(db, await schluesselFuer('cod-e', email), 5, 60 * MINUTE, jetzt, 'Für diese Adresse wurden zu viele Codes angefordert.');
  await bremsen(db, await schluesselFuer('cod-i', ip), 20, 60 * MINUTE, jetzt, 'Von hier wurden zu viele Codes angefordert.');
  pepper(env);
  const dev = await codeSenden(env, db, email, 'anmelden', jetzt);
  return Object.assign({}, ANTWORT_CODE, dev ? { entwicklungsCode: dev } : {});
}

async function codePruefen(request, env, db, jetzt) {
  const b = await bodyLesen(request);
  const email = emailNormal(b.email);
  const code = typeof b.code === 'string' ? b.code.replace(/\s+/g, '') : '';
  if (!/^\d{6}$/.test(code)) throw new HttpFehler(400, 'Der Code besteht aus sechs Ziffern.', { feld: 'code' });
  const ip = request.headers.get('CF-Connecting-IP') || 'unbekannt';
  await bremsen(db, await schluesselFuer('pru-i', ip), 40, 15 * MINUTE, jetzt, 'Von hier wurden zu viele Codes geprüft.');
  const g = pepper(env);
  const z = await db.prepare('SELECT zweck, code_hash, laeuft_ab, versuche FROM code WHERE email = ?').bind(email).first();
  const falsch = 'Der Code ist falsch oder abgelaufen. Fordere bei Bedarf einen neuen an.';
  if (!z || z.laeuft_ab <= jetzt) throw new HttpFehler(400, falsch, { feld: 'code' });
  if (z.versuche >= CODE_VERSUCHE) {
    await db.prepare('DELETE FROM code WHERE email = ?').bind(email).run();
    throw new HttpFehler(400, 'Zu viele falsche Eingaben. Fordere einen neuen Code an.', { feld: 'code' });
  }
  const ist = new Uint8Array(await hmac(g, email + ':' + code));
  let soll;
  try { soll = Uint8Array.from(z.code_hash.match(/../g).map((x) => parseInt(x, 16))); } catch (e) { soll = new Uint8Array(0); }
  if (!gleich(ist, soll)) {
    await db.prepare('UPDATE code SET versuche = versuche + 1 WHERE email = ?').bind(email).run();
    throw new HttpFehler(400, falsch, { feld: 'code' });
  }
  /* Der Code gilt nur einmal. */
  await db.prepare('DELETE FROM code WHERE email = ?').bind(email).run();

  let n = await db.prepare('SELECT id, passwort_wartend, bestaetigt_am FROM nutzer WHERE email = ?').bind(email).first();
  const neuBestaetigt = !n || !n.bestaetigt_am;
  const stmts = [];
  let id;
  if (!n) {
    id = crypto.randomUUID();
    stmts.push(db.prepare('INSERT INTO nutzer (id, email, erstellt_am, bestaetigt_am, letzte_anmeldung) VALUES (?, ?, ?, ?, ?)').bind(id, email, jetzt, jetzt, jetzt));
  } else {
    id = n.id;
    if (z.zweck === 'registrieren' && n.passwort_wartend) {
      stmts.push(db.prepare('UPDATE nutzer SET passwort_hash = passwort_wartend, passwort_wartend = NULL, bestaetigt_am = COALESCE(bestaetigt_am, ?), letzte_anmeldung = ? WHERE id = ?').bind(jetzt, jetzt, id));
    } else {
      /* Ein Code zum Anmelden macht ein vorgemerktes Passwort ungültig. */
      stmts.push(db.prepare('UPDATE nutzer SET passwort_wartend = NULL, bestaetigt_am = COALESCE(bestaetigt_am, ?), letzte_anmeldung = ? WHERE id = ?').bind(jetzt, jetzt, id));
    }
  }
  stmts.push(db.prepare('INSERT OR IGNORE INTO datenraum (id, nutzer_id, name, erstellt_am) VALUES (?, ?, ?, ?)').bind(crypto.randomUUID(), id, 'Mein Datenraum', jetzt));
  await db.batch(stmts);
  /* 13e: Die Testwoche gibt es einmal je bestätigter E-Mail-Adresse, nur beim ersten Bestätigen. */
  if (neuBestaetigt) await testwocheStarten(db, env, id, email, jetzt);
  return sitzungAnwort(db, id, geraetName(b.geraet), jetzt);
}

async function anmelden(request, env, db, jetzt) {
  const b = await bodyLesen(request);
  const email = emailNormal(b.email);
  const pw = typeof b.passwort === 'string' ? b.passwort : '';
  if (!pw || kodieren.encode(pw).length > MAX_PASSWORT_BYTES) throw new HttpFehler(401, 'E-Mail oder Passwort passen nicht.');
  const ip = request.headers.get('CF-Connecting-IP') || 'unbekannt';
  await bremsen(db, await schluesselFuer('anm-e', email), 10, 15 * MINUTE, jetzt, 'Zu viele Versuche für diese Adresse.');
  await bremsen(db, await schluesselFuer('anm-i', ip), 40, 15 * MINUTE, jetzt, 'Zu viele Versuche von hier.');
  const g = pepper(env);
  const n = await db.prepare('SELECT id, passwort_hash, bestaetigt_am FROM nutzer WHERE email = ?').bind(email).first();
  const abgewiesen = new HttpFehler(401, 'E-Mail oder Passwort passen nicht.');
  if (!n || !n.passwort_hash || !n.bestaetigt_am) { await blindPruefen(pw, g); throw abgewiesen; }
  const r = await passwortPruefen(pw, n.passwort_hash, g);
  if (!r.ok) throw abgewiesen;
  if (r.veraltet) await db.prepare('UPDATE nutzer SET passwort_hash = ? WHERE id = ?').bind(await passwortHashen(pw, g), n.id).run();
  await db.prepare('UPDATE nutzer SET letzte_anmeldung = ? WHERE id = ?').bind(jetzt, n.id).run();
  return sitzungAnwort(db, n.id, geraetName(b.geraet), jetzt);
}

async function ich(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const d = await db.prepare('SELECT id, name FROM datenraum WHERE nutzer_id = ?').bind(a.id).first();
  return { ok: true, email: a.email, datenraum: d ? { id: d.id, name: d.name } : null, passwortGesetzt: a.passwortGesetzt, laeuftAb: a.laeuftAb };
}

async function passwortSetzen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  const pw = passwortRegeln(b.passwort);
  const hash = await passwortHashen(pw, pepper(env));
  await db.batch([
    db.prepare('UPDATE nutzer SET passwort_hash = ?, passwort_wartend = NULL WHERE id = ?').bind(hash, a.id),
    db.prepare('DELETE FROM sitzung WHERE nutzer_id = ? AND token_hash <> ?').bind(a.id, a.hash)
  ]);
  return { ok: true };
}

async function abmelden(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  await db.prepare('DELETE FROM sitzung WHERE token_hash = ?').bind(a.hash).run();
  return { ok: true };
}

/* Löscht das Konto samt Datenraum und allen Sitzungen. Die Dateien in R2 werden mit gelöscht (13d). */
async function loeschen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  if (b.bestaetigung !== 'LÖSCHEN') throw new HttpFehler(400, 'Zum Löschen muss das Wort LÖSCHEN eingegeben werden.', { feld: 'bestaetigung' });
  if (a.datenraumId) { try { await datenraumLeeren(db, a.datenraumId, true, env); } catch (e) { /* Tabellen von 13b noch nicht angelegt: nichts zu löschen */ } }
  await db.batch([
    db.prepare('DELETE FROM sitzung WHERE nutzer_id = ?').bind(a.id),
    db.prepare('DELETE FROM datenraum WHERE nutzer_id = ?').bind(a.id),
    db.prepare('DELETE FROM code WHERE email = ?').bind(a.email),
    db.prepare('DELETE FROM nutzer WHERE id = ?').bind(a.id)
  ]);
  return { ok: true };
}

/* ---------- 13b: Abgleich zwischen Geräten ---------- */

/* Nur diese Datenarten nimmt der Dienst an. Die gleichen Listen stehen in js/abgleich.js (ein Test vergleicht sie). */
export const ABGLEICH_TABELLEN = ['fahrzeuge', 'eintraege', 'komponenten', 'komponenteneintraege', 'zaehler', 'zaehlerstaende', 'fristen', 'durchfuehrungen',
  'vorgaenge', 'vorgangsentscheidungen', 'aktivitaeten', 'aktivitaetsarten', 'besatzung', 'verantwortung', 'tagesabschnitte', 'ereignisse', 'ereignisarten',
  'tagespruefungen', 'personen', 'tiere', 'adressen', 'orte', 'gebiete', 'regeln', 'verlaeufe',
  'dokumente', 'dateien', 'ereignisdateien', 'nachweisarten', 'nachweise', 'nachweisdateien',
  'kosten', 'kostenstamm', 'kostenarten', 'zahlungsmittel', 'kassen', 'kassenbuchungen', 'routen', 'besuche', 'reisechecks'];
export const ABGLEICH_VERLAUF_TYPEN = ['zaehler', 'frist', 'vorgang', 'aktivitaet', 'besatzung', 'verantwortung', 'tagesabschnitt', 'ereignis', 'aktivitaetsart',
  'ereignisart', 'ort', 'gebiet', 'regel', 'person', 'tier', 'adresse',
  'dokument', 'kosten', 'kostenstamm', 'kostenart', 'zahlungsmittel', 'kassenbuchung', 'besuch', 'route', 'nachweisart', 'nachweis'];
/* Vom Nachweis gehen nur diese Angaben hinaus (Nummer, Aussteller, Klassen und Notiz bleiben auf dem Gerät). */
export const NACHWEIS_FELDER = ['ausgestelltAm', 'gueltigBis', 'dateiName', 'dateiTyp', 'dateiGroesse'];
/* Das Feld „namen“ des Reisechecks (Namen hinter den Decknamen) bleibt auf dem Gerät. */
export const EXTRA_LOKAL = { reisechecks: ['namen'] };
export const DATEI_TABELLEN = ['dateien', 'nachweisdateien', 'ereignisdateien'];
/* Diese Angaben bleiben auf dem Gerät. Taucht einer dieser Schlüssel in einem Datensatz auf, lehnt der Dienst ihn ab. */
export const LOKALE_SCHLUESSEL = ['notiz', 'abschlussNotiz', 'erledigtNotiz', 'email', 'telefon', 'chipnummer', 'adresse', 'ansprechpartner',
  'geburtsdatum', 'wohnort', 'inhalt', 'spur'];

function raumVon(a) {
  if (!a.datenraumId) throw new HttpFehler(409, 'Zu diesem Konto gibt es keinen Datenraum.');
  return a.datenraumId;
}

function verbotenerSchluessel(o) {
  if (Array.isArray(o)) { for (const x of o) { const r = verbotenerSchluessel(x); if (r) return r; } return null; }
  if (o && typeof o === 'object') {
    for (const k of Object.keys(o)) { if (LOKALE_SCHLUESSEL.includes(k)) return k; const r = verbotenerSchluessel(o[k]); if (r) return r; }
  }
  return null;
}

/* Prüft einen Datensatz aus der App. Gibt die Werte für die Datenbank zurück. */
function satzPruefen(d) {
  if (!d || typeof d !== 'object') throw new HttpFehler(400, 'Ein Datensatz ist ungültig.');
  if (typeof d.tabelle !== 'string' || !ABGLEICH_TABELLEN.includes(d.tabelle)) throw new HttpFehler(400, 'Diese Datenart nimmt der Dienst nicht an.', { feld: 'tabelle' });
  if (typeof d.id !== 'string' || !/^[A-Za-z0-9_.:-]{1,100}$/.test(d.id)) throw new HttpFehler(400, 'Eine Kennung ist ungültig.', { feld: 'id' });
  const basis = Number.isInteger(d.basis) && d.basis >= 0 ? d.basis : -1;
  if (basis < 0) throw new HttpFehler(400, 'Eine Angabe zum Stand fehlt.', { feld: 'basis' });
  if (d.geloescht === true) return { tabelle: d.tabelle, id: d.id, basis, geloescht: true, nutzlast: null, fahrzeugId: null };
  if (typeof d.nutzlast !== 'string' || !d.nutzlast || d.nutzlast.length > MAX_ABGLEICH_NUTZLAST) throw new HttpFehler(400, 'Ein Datensatz ist leer oder zu groß.', { feld: 'nutzlast' });
  let o;
  try { o = JSON.parse(d.nutzlast); } catch (e) { throw new HttpFehler(400, 'Ein Datensatz ist kein gültiger Text.', { feld: 'nutzlast' }); }
  if (!o || typeof o !== 'object' || Array.isArray(o) || o.id !== d.id) throw new HttpFehler(400, 'Ein Datensatz passt nicht zu seiner Kennung.', { feld: 'nutzlast' });
  if (d.tabelle === 'verlaeufe' && !ABGLEICH_VERLAUF_TYPEN.includes(o.objektTyp)) throw new HttpFehler(400, 'Diese Art von Änderung nimmt der Dienst nicht an.', { feld: 'nutzlast' });
  const v = verbotenerSchluessel(o);
  if (v) throw new HttpFehler(400, 'Die Angabe „' + v + '“ bleibt auf dem Gerät und wird nicht angenommen.', { feld: 'nutzlast' });
  for (const n of (EXTRA_LOKAL[d.tabelle] || [])) { if (Object.prototype.hasOwnProperty.call(o, n)) throw new HttpFehler(400, 'Die Angabe „' + n + '“ bleibt auf dem Gerät und wird nicht angenommen.', { feld: 'nutzlast' }); }
  if (d.tabelle === 'verlaeufe' && o.objektTyp === 'nachweis' && o.werte && typeof o.werte === 'object') {
    for (const n of Object.keys(o.werte)) { if (!NACHWEIS_FELDER.includes(n)) throw new HttpFehler(400, 'Die Angabe „' + n + '“ zum Nachweis bleibt auf dem Gerät und wird nicht angenommen.', { feld: 'nutzlast' }); }
  }
  let fz = d.tabelle === 'fahrzeuge' ? d.id : (typeof o.fahrzeugId === 'string' ? o.fahrzeugId : null);
  if (fz && fz.length > 100) fz = null;
  return { tabelle: d.tabelle, id: d.id, basis, geloescht: false, nutzlast: d.nutzlast, fahrzeugId: fz };
}

async function abgleichStand(db, dr) {
  await db.prepare('INSERT OR IGNORE INTO abgleich_stand (datenraum_id, seq, epoche) VALUES (?, 0, ?)').bind(dr, crypto.randomUUID()).run();
  return db.prepare('SELECT seq, epoche FROM abgleich_stand WHERE datenraum_id = ?').bind(dr).first();
}

async function abgleichStandWeg(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const z = await abgleichStand(db, dr);
  const n = await db.prepare('SELECT COUNT(*) AS n FROM abgleich WHERE datenraum_id = ? AND geloescht = 0').bind(dr).first();
  return { ok: true, seq: z.seq, epoche: z.epoche, anzahl: n ? n.n : 0 };
}

async function abgleichAenderungen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const seit = Math.max(0, parseInt(new URL(request.url).searchParams.get('seit') || '0', 10) || 0);
  const z = await abgleichStand(db, dr);
  const r = await db.prepare('SELECT tabelle, objekt_id, seq, geloescht, nutzlast FROM abgleich WHERE datenraum_id = ? AND seq > ? ORDER BY seq LIMIT ?').bind(dr, seit, HOL_SEITE + 1).all();
  const alle = r.results || [], weiter = alle.length > HOL_SEITE, seite = alle.slice(0, HOL_SEITE);
  return { ok: true, epoche: z.epoche, seq: z.seq, weiter, bis: seite.length ? seite[seite.length - 1].seq : seit,
    eintraege: seite.map((x) => ({ tabelle: x.tabelle, id: x.objekt_id, seq: x.seq, geloescht: !!x.geloescht, nutzlast: x.geloescht ? null : x.nutzlast })) };
}

/* Schreibt ein Paket. „basis“ ist der Stand, den die App von diesem Datensatz kennt (0 = neu). Stimmt er nicht mehr, wird nichts überschrieben,
   der Datensatz kommt als Konflikt mit dem Stand des Dienstes zurück. */
async function abgleichSenden(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const b = await bodyLesen(request, MAX_ABGLEICH_BODY);
  const roh = Array.isArray(b.eintraege) ? b.eintraege : [];
  if (!roh.length || roh.length > MAX_PAKET) throw new HttpFehler(400, 'Ein Paket enthält 1 bis ' + MAX_PAKET + ' Datensätze.');
  const sauber = roh.map(satzPruefen), doppelt = {};
  sauber.forEach((x) => { const k = x.tabelle + '/' + x.id; if (doppelt[k]) throw new HttpFehler(400, 'Ein Datensatz steht zweimal im Paket.'); doppelt[k] = true; });
  await abgleichStand(db, dr);
  const z = await db.prepare('UPDATE abgleich_stand SET seq = seq + ? WHERE datenraum_id = ? RETURNING seq, epoche').bind(sauber.length, dr).first();
  const erste = z.seq - sauber.length;
  const res = await db.batch(sauber.map((x, i) => db.prepare('INSERT INTO abgleich (datenraum_id, tabelle, objekt_id, seq, geloescht, fahrzeug_id, nutzlast, geaendert_am) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(datenraum_id, tabelle, objekt_id) DO UPDATE SET seq = excluded.seq, geloescht = excluded.geloescht, fahrzeug_id = excluded.fahrzeug_id, nutzlast = excluded.nutzlast, geaendert_am = excluded.geaendert_am WHERE abgleich.seq = ?')
    .bind(dr, x.tabelle, x.id, erste + i + 1, x.geloescht ? 1 : 0, x.fahrzeugId, x.nutzlast, jetzt, x.basis)));
  const angenommen = [], streit = [];
  sauber.forEach((x, i) => {
    const ch = res[i] && res[i].meta ? res[i].meta.changes : 0;
    if (ch > 0) angenommen.push({ tabelle: x.tabelle, id: x.id, seq: erste + i + 1 }); else streit.push(x);
  });
  let konflikte = [];
  if (streit.length) {
    const bed = streit.map(() => '(tabelle = ? AND objekt_id = ?)').join(' OR ');
    const werte = [dr]; streit.forEach((x) => { werte.push(x.tabelle, x.id); });
    const r = await db.prepare('SELECT tabelle, objekt_id, seq, geloescht, nutzlast FROM abgleich WHERE datenraum_id = ? AND (' + bed + ')').bind(...werte).all();
    konflikte = (r.results || []).map((x) => ({ tabelle: x.tabelle, id: x.objekt_id, seq: x.seq, geloescht: !!x.geloescht, nutzlast: x.geloescht ? null : x.nutzlast }));
  }
  return { ok: true, epoche: z.epoche, seq: z.seq, angenommen, konflikte };
}

/* Leert den Datenraum beim Dienst. ganz = auch die Sicherungen (beim Löschen des Kontos). */
async function datenraumLeeren(db, dr, ganz, env) {
  await dateienLoeschen(env, db, dr);
  const l = [];
  if (ganz) {
    l.push(db.prepare('DELETE FROM sicherungsteil WHERE sicherung_id IN (SELECT id FROM sicherung WHERE datenraum_id = ?)').bind(dr));
    l.push(db.prepare('DELETE FROM sicherung WHERE datenraum_id = ?').bind(dr));
  }
  l.push(db.prepare('DELETE FROM abgleich WHERE datenraum_id = ?').bind(dr));
  /* Die Kennung des Standes ändert sich beim nächsten Zugriff, andere Geräte merken das und gleichen von vorn ab. */
  l.push(db.prepare('DELETE FROM abgleich_stand WHERE datenraum_id = ?').bind(dr));
  await db.batch(l);
}

async function abgleichLeeren(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const b = await bodyLesen(request);
  if (b.bestaetigung !== 'LÖSCHEN') throw new HttpFehler(400, 'Zum Löschen muss das Wort LÖSCHEN eingegeben werden.', { feld: 'bestaetigung' });
  await datenraumLeeren(db, dr, false, env);
  return { ok: true };
}

/* ---------- 13d: Dateien (Fotos, Scans, Dokumente) in R2 ---------- */

function dateiSpeicher(env) {
  if (!env || !env.DATEN) throw new HttpFehler(503, 'Der Dateispeicher (R2) ist beim Dienst noch nicht eingerichtet. Siehe EINRICHTUNG.md, Abschnitt „Update auf 13d“.');
  return env.DATEN;
}

function dateiZiel(url) {
  const tabelle = url.searchParams.get('tabelle') || '', id = url.searchParams.get('id') || '';
  if (!DATEI_TABELLEN.includes(tabelle)) throw new HttpFehler(400, 'Diese Art von Datei nimmt der Dienst nicht an.', { feld: 'tabelle' });
  if (!/^[A-Za-z0-9_.:-]{1,100}$/.test(id)) throw new HttpFehler(400, 'Eine Kennung ist ungültig.', { feld: 'id' });
  return { tabelle, id };
}

function dateiPfad(dr, tabelle, id) { return dr + '/' + tabelle + '/' + id; }

/* Nimmt eine Datei an. Der Inhalt kommt als Bytes im Körper der Anfrage (Content-Length nötig), er wird nicht in den Arbeitsspeicher gelesen. */
async function dateiHochladen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const r2 = dateiSpeicher(env);
  const z = dateiZiel(new URL(request.url));
  const laenge = parseInt(request.headers.get('Content-Length') || '', 10);
  if (!Number.isInteger(laenge) || laenge < 1 || !request.body) throw new HttpFehler(411, 'Die Datei ist leer oder ihre Größe fehlt.');
  if (laenge > MAX_DATEI_BYTES) throw new HttpFehler(413, 'Die Datei ist zu groß (höchstens ' + (MAX_DATEI_BYTES / 1048576) + ' MB).', { feld: 'groesse' });
  const verschluesselt = new URL(request.url).searchParams.get('verschluesselt') === '1' ? 1 : 0;
  const belegt = await db.prepare('SELECT COALESCE(SUM(groesse), 0) AS n FROM datei WHERE datenraum_id = ? AND NOT (tabelle = ? AND objekt_id = ?)').bind(dr, z.tabelle, z.id).first();
  if ((belegt ? belegt.n : 0) + laenge > MAX_KONTO_DATEI_BYTES) throw new HttpFehler(413, 'Der Speicherplatz dieses Kontos ist voll (' + (MAX_KONTO_DATEI_BYTES / 1073741824) + ' GB).', { feld: 'groesse' });
  const pfad = dateiPfad(dr, z.tabelle, z.id);
  const o = await r2.put(pfad, request.body);
  if (!o || o.size !== laenge) {
    try { await r2.delete(pfad); } catch (e) { /* nichts zu tun */ }
    throw new HttpFehler(400, 'Die Datei ist nicht vollständig angekommen. Bitte noch einmal versuchen.');
  }
  await db.prepare('INSERT INTO datei (datenraum_id, tabelle, objekt_id, groesse, verschluesselt, erstellt_am) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(datenraum_id, tabelle, objekt_id) DO UPDATE SET groesse = excluded.groesse, verschluesselt = excluded.verschluesselt, erstellt_am = excluded.erstellt_am')
    .bind(dr, z.tabelle, z.id, laenge, verschluesselt, jetzt).run();
  return { ok: true, groesse: laenge, verschluesselt: !!verschluesselt };
}

/* Gibt die Bytes einer Datei zurück (kein JSON). */
async function dateiHolen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const r2 = dateiSpeicher(env);
  const z = dateiZiel(new URL(request.url));
  const m = await db.prepare('SELECT groesse, verschluesselt FROM datei WHERE datenraum_id = ? AND tabelle = ? AND objekt_id = ?').bind(dr, z.tabelle, z.id).first();
  if (!m) throw new HttpFehler(404, 'Diese Datei liegt nicht beim Dienst.');
  const o = await r2.get(dateiPfad(dr, z.tabelle, z.id));
  if (!o) throw new HttpFehler(404, 'Diese Datei liegt nicht beim Dienst.');
  return new Response(o.body, { status: 200, headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(m.groesse), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Verschluesselt': m.verschluesselt ? '1' : '0' } });
}

async function dateiListe(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const nach = new URL(request.url).searchParams.get('nach') || '';
  const r = await db.prepare("SELECT tabelle, objekt_id, groesse, verschluesselt FROM datei WHERE datenraum_id = ? AND (tabelle || '/' || objekt_id) > ? ORDER BY (tabelle || '/' || objekt_id) LIMIT ?").bind(dr, nach, DATEI_SEITE + 1).all();
  const alle = r.results || [], weiter = alle.length > DATEI_SEITE, seite = alle.slice(0, DATEI_SEITE);
  const sum = await db.prepare('SELECT COALESCE(SUM(groesse), 0) AS n FROM datei WHERE datenraum_id = ?').bind(dr).first();
  return { ok: true, weiter, nach: seite.length ? seite[seite.length - 1].tabelle + '/' + seite[seite.length - 1].objekt_id : nach, belegt: sum ? sum.n : 0, grenze: MAX_KONTO_DATEI_BYTES,
    dateien: seite.map((x) => ({ tabelle: x.tabelle, id: x.objekt_id, groesse: x.groesse, verschluesselt: !!x.verschluesselt })) };
}

async function dateiLoeschenWeg(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const r2 = dateiSpeicher(env);
  const b = await bodyLesen(request);
  const z = dateiZiel(new URL('https://x/?tabelle=' + encodeURIComponent(String(b.tabelle || '')) + '&id=' + encodeURIComponent(String(b.id || ''))));
  await r2.delete(dateiPfad(dr, z.tabelle, z.id));
  await db.prepare('DELETE FROM datei WHERE datenraum_id = ? AND tabelle = ? AND objekt_id = ?').bind(dr, z.tabelle, z.id).run();
  return { ok: true };
}

/* Löscht alle Dateien eines Datenraums (beim Leeren und beim Löschen des Kontos). Fehlt R2 oder die Tabelle, ist nichts zu löschen. */
async function dateienLoeschen(env, db, dr) {
  if (env && env.DATEN) {
    let weiter = true;
    while (weiter) {
      const l = await env.DATEN.list({ prefix: dr + '/', limit: 1000 });
      const keys = (l.objects || []).map((x) => x.key);
      if (keys.length) await env.DATEN.delete(keys);
      weiter = !!l.truncated && keys.length > 0;
    }
  }
  try { await db.prepare('DELETE FROM datei WHERE datenraum_id = ?').bind(dr).run(); } catch (e) { if (!/no such table/i.test(String(e && e.message || e))) throw e; }
}

/* ---------- 13b: verschlüsselte Sicherung (der Dienst sieht nur Bytes) ---------- */

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

async function sicherungAnfangen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const b = await bodyLesen(request);
  const groesse = Number.isInteger(b.groesse) ? b.groesse : -1;
  if (groesse < 1 || groesse > MAX_SICHERUNG_BYTES) throw new HttpFehler(400, 'Die Sicherung ist zu groß für den Dienst (höchstens ' + (MAX_SICHERUNG_BYTES / 1048576) + ' MB). Sichere ohne Dateien.', { feld: 'groesse' });
  if (typeof b.summe !== 'string' || !/^[0-9a-f]{64}$/.test(b.summe)) throw new HttpFehler(400, 'Die Prüfsumme fehlt.', { feld: 'summe' });
  const id = crypto.randomUUID(), teile = Math.ceil(groesse / TEIL_BYTES);
  await db.batch([
    db.prepare('DELETE FROM sicherungsteil WHERE sicherung_id IN (SELECT id FROM sicherung WHERE datenraum_id = ? AND fertig = 0)').bind(dr),
    db.prepare('DELETE FROM sicherung WHERE datenraum_id = ? AND fertig = 0').bind(dr),
    db.prepare('INSERT INTO sicherung (id, datenraum_id, erstellt_am, app, groesse, teile, summe, fertig) VALUES (?, ?, ?, ?, ?, ?, ?, 0)').bind(id, dr, jetzt, typeof b.app === 'string' ? b.app.slice(0, 40) : null, groesse, teile, b.summe)
  ]);
  return { ok: true, id, teile, teilBytes: TEIL_BYTES };
}

async function sicherungTeil(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const b = await bodyLesen(request, MAX_BASE64_TEIL + 1024);
  const s = await db.prepare('SELECT teile, fertig FROM sicherung WHERE id = ? AND datenraum_id = ?').bind(String(b.id || ''), dr).first();
  if (!s || s.fertig) throw new HttpFehler(404, 'Diese Sicherung gibt es nicht oder sie ist schon fertig.');
  if (!Number.isInteger(b.nr) || b.nr < 0 || b.nr >= s.teile) throw new HttpFehler(400, 'Die Nummer des Teils passt nicht.', { feld: 'nr' });
  if (typeof b.daten !== 'string' || !b.daten || b.daten.length > MAX_BASE64_TEIL || !BASE64.test(b.daten)) throw new HttpFehler(400, 'Der Teil ist ungültig oder zu groß.', { feld: 'daten' });
  await db.prepare('INSERT OR REPLACE INTO sicherungsteil (sicherung_id, nr, daten) VALUES (?, ?, ?)').bind(b.id, b.nr, b.daten).run();
  return { ok: true };
}

async function sicherungFertig(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const b = await bodyLesen(request);
  const s = await db.prepare('SELECT teile, fertig FROM sicherung WHERE id = ? AND datenraum_id = ?').bind(String(b.id || ''), dr).first();
  if (!s || s.fertig) throw new HttpFehler(404, 'Diese Sicherung gibt es nicht oder sie ist schon fertig.');
  const n = await db.prepare('SELECT COUNT(*) AS n FROM sicherungsteil WHERE sicherung_id = ?').bind(b.id).first();
  if (!n || n.n !== s.teile) throw new HttpFehler(400, 'Es fehlen Teile der Sicherung. Bitte noch einmal sichern.');
  const alte = await db.prepare('SELECT id FROM sicherung WHERE datenraum_id = ? AND fertig = 1 ORDER BY erstellt_am DESC, id DESC LIMIT -1 OFFSET ?').bind(dr, SICHERUNGEN_BEHALTEN - 1).all();
  const weg = (alte.results || []).map((x) => x.id);
  const l = [db.prepare('UPDATE sicherung SET fertig = 1 WHERE id = ?').bind(b.id)];
  weg.forEach((id) => { l.push(db.prepare('DELETE FROM sicherungsteil WHERE sicherung_id = ?').bind(id), db.prepare('DELETE FROM sicherung WHERE id = ?').bind(id)); });
  await db.batch(l);
  return { ok: true, entfernt: weg.length };
}

async function sicherungListe(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const r = await db.prepare('SELECT id, erstellt_am, app, groesse, teile, summe FROM sicherung WHERE datenraum_id = ? AND fertig = 1 ORDER BY erstellt_am DESC, id DESC').bind(dr).all();
  return { ok: true, sicherungen: (r.results || []).map((x) => ({ id: x.id, erstelltAm: x.erstellt_am, app: x.app, groesse: x.groesse, teile: x.teile, summe: x.summe })) };
}

async function sicherungHolen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const u = new URL(request.url), id = u.searchParams.get('id') || '', nr = parseInt(u.searchParams.get('nr') || '', 10);
  const t = await db.prepare('SELECT t.daten AS daten FROM sicherungsteil t JOIN sicherung s ON s.id = t.sicherung_id WHERE s.id = ? AND s.datenraum_id = ? AND s.fertig = 1 AND t.nr = ?').bind(id, dr, Number.isInteger(nr) ? nr : -1).first();
  if (!t) throw new HttpFehler(404, 'Dieser Teil der Sicherung wurde nicht gefunden.');
  return { ok: true, daten: t.daten };
}

async function sicherungLoeschen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const b = await bodyLesen(request);
  const id = String(b.id || '');
  await db.batch([
    db.prepare('DELETE FROM sicherungsteil WHERE sicherung_id IN (SELECT id FROM sicherung WHERE id = ? AND datenraum_id = ?)').bind(id, dr),
    db.prepare('DELETE FROM sicherung WHERE id = ? AND datenraum_id = ?').bind(id, dr)
  ]);
  return { ok: true };
}

/* ---------- 13c: Freigaben (je Fahrzeug und Zeitraum) und Kontroll-Freigabe per Code ---------- */

/* Ein Gast liest nur über die Wege „/geteilt/…“, nie über die Wege des Abgleichs (die gelten immer nur für den eigenen Datenraum).
   Schreiben darf ein Gast nirgends. Die Rechte werden bei jeder Anfrage neu geprüft: Konto, Annahme, Zeitraum, Widerruf. */
const CODE_ZEICHEN = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
const EINLADUNG_CODE_LAENGE = 10;
const KONTROLLE_CODE_LAENGE = 8;
const EINLADUNG_TAGE = 14;
const MAX_FREIGABEN = 50;
const MAX_KONTROLLEN = 10;
const KONTROLLE_MAX_STUNDEN = 168;
const KONTROLLE_STANDARD_STUNDEN = 24;
const FREIGABE_MONATE = 12;
const SICHT_DURCHFUEHRUNGEN = 500;
const SICHT_STAENDE = 200;

function zufallCode(laenge) {
  const grenze = 256 - (256 % CODE_ZEICHEN.length);
  let s = '';
  while (s.length < laenge) {
    for (const b of crypto.getRandomValues(new Uint8Array(laenge * 2))) {
      if (b < grenze && s.length < laenge) s += CODE_ZEICHEN[b % CODE_ZEICHEN.length];
    }
  }
  return s;
}

/* Code aus der Eingabe: Groß, ohne Leerzeichen und Striche. Gibt null zurück, wenn er nicht passt. */
function codeSauber(roh, laenge) {
  const t = typeof roh === 'string' ? roh.toUpperCase().replace(/[\s-]+/g, '') : '';
  if (t.length !== laenge) return null;
  for (const c of t) { if (CODE_ZEICHEN.indexOf(c) < 0) return null; }
  return t;
}

async function codeAbdruck(env, zweck, code) { return zuHex(await hmac(pepper(env), zweck + ':' + code)); }

function datumTeile(t) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(typeof t === 'string' ? t : '');
  if (!m) return null;
  const y = +m[1], mo = +m[2], d = +m[3];
  const x = new Date(Date.UTC(y, mo - 1, d));
  return x.getUTCFullYear() === y && x.getUTCMonth() === mo - 1 && x.getUTCDate() === d ? { y, mo, d } : null;
}
function datumText(ms) { return new Date(ms).toISOString().slice(0, 10); }
function tagAnfang(text) { const t = datumTeile(text); return Date.UTC(t.y, t.mo - 1, t.d, 0, 0, 0, 0); }
function tagEnde(text) { const t = datumTeile(text); return Date.UTC(t.y, t.mo - 1, t.d, 23, 59, 59, 999); }
/* Datum plus Monate, Monatsende bleibt Monatsende. */
function plusMonate(text, n) {
  const t = datumTeile(text), gesamt = t.y * 12 + (t.mo - 1) + n, y = Math.floor(gesamt / 12), mo = (gesamt % 12) + 1;
  const tage = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  return datumText(Date.UTC(y, mo - 1, Math.min(t.d, tage)));
}

function kennung(roh, name) {
  if (typeof roh !== 'string' || !/^[A-Za-z0-9_.:-]{1,100}$/.test(roh)) throw new HttpFehler(400, 'Eine Kennung ist ungültig.', { feld: name || 'id' });
  return roh;
}

/* Das Fahrzeug muss im Datenraum des Besitzers liegen und darf nicht gelöscht sein. */
async function fahrzeugDa(db, dr, fz) {
  const r = await db.prepare("SELECT 1 AS da FROM abgleich WHERE datenraum_id = ? AND tabelle = 'fahrzeuge' AND objekt_id = ? AND geloescht = 0").bind(dr, fz).first();
  return !!r;
}

function freigabeStatus(f, jetzt) {
  if (f.widerrufen_am) return 'widerrufen';
  if (!f.angenommen_am) return f.einladung_bis <= jetzt || f.laeuft_ab <= jetzt ? 'abgelaufen' : 'eingeladen';
  if (f.laeuft_ab <= jetzt) return 'abgelaufen';
  if (f.ab_am > jetzt) return 'wartet';
  return 'aktiv';
}

const NAME_VON_FAHRZEUG = "(SELECT json_extract(e.nutzlast, '$.werte.bezeichnung') FROM abgleich e WHERE e.datenraum_id = f.datenraum_id AND e.tabelle = 'eintraege' AND e.fahrzeug_id = f.fahrzeug_id AND e.geloescht = 0 ORDER BY json_extract(e.nutzlast, '$.nr') DESC LIMIT 1)";

/* Der Besitzer lädt ein: Fahrzeug, E-Mail-Adresse des Gastes, Zeitraum (höchstens 12 Monate). Der Gast bekommt einen Code. */
async function freigabeEinladen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const b = await bodyLesen(request);
  const fz = kennung(b.fahrzeugId, 'fahrzeugId');
  const email = emailNormal(b.email);
  if (email === a.email) throw new HttpFehler(400, 'Das ist deine eigene Adresse. Eine Freigabe an dich selbst gibt es nicht.', { feld: 'email' });
  const heute = datumText(jetzt);
  const ab = b.ab === undefined || b.ab === null || b.ab === '' ? heute : b.ab;
  if (!datumTeile(ab)) throw new HttpFehler(400, 'Das Datum „von“ ist ungültig.', { feld: 'ab' });
  if (!datumTeile(b.bis)) throw new HttpFehler(400, 'Das Datum „bis“ ist ungültig.', { feld: 'bis' });
  if (ab < heute) throw new HttpFehler(400, 'Das Datum „von“ liegt in der Vergangenheit.', { feld: 'ab' });
  if (b.bis < ab) throw new HttpFehler(400, 'Das Datum „bis“ liegt vor dem Datum „von“.', { feld: 'bis' });
  if (b.bis > plusMonate(ab, FREIGABE_MONATE)) throw new HttpFehler(400, 'Eine Freigabe gilt höchstens ' + FREIGABE_MONATE + ' Monate.', { feld: 'bis' });
  if (!(await fahrzeugDa(db, dr, fz))) throw new HttpFehler(404, 'Dieses Fahrzeug liegt nicht beim Dienst. Bitte zuerst unter Funktionen › Konto abgleichen.', { feld: 'fahrzeugId' });
  await bremsen(db, await schluesselFuer('fre-e', a.id), 20, 60 * MINUTE, jetzt, 'Du hast in kurzer Zeit zu viele Einladungen verschickt.');
  const offen = await db.prepare('SELECT COUNT(*) AS n FROM freigabe WHERE datenraum_id = ? AND widerrufen_am IS NULL AND laeuft_ab > ?').bind(dr, jetzt).first();
  if (offen && offen.n >= MAX_FREIGABEN) throw new HttpFehler(409, 'Es gibt schon ' + MAX_FREIGABEN + ' gültige Freigaben. Bitte widerrufe zuerst eine.');
  const code = zufallCode(EINLADUNG_CODE_LAENGE);
  const id = crypto.randomUUID();
  const laeuftAb = tagEnde(b.bis), abAm = tagAnfang(ab), einladungBis = Math.min(laeuftAb, jetzt + EINLADUNG_TAGE * TAG);
  /* Gleiches Fahrzeug und gleicher Gast: Die ältere Freigabe wird ersetzt. */
  await db.batch([
    db.prepare('UPDATE freigabe SET widerrufen_am = ? WHERE datenraum_id = ? AND fahrzeug_id = ? AND email = ? AND widerrufen_am IS NULL').bind(jetzt, dr, fz, email),
    db.prepare('INSERT INTO freigabe (id, datenraum_id, fahrzeug_id, email, code_hash, erstellt_am, ab_am, laeuft_ab, einladung_bis) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, dr, fz, email, await codeAbdruck(env, 'freigabe', code), jetzt, abAm, laeuftAb, einladungBis)
  ]);
  let r;
  try {
    r = await mailSenden(env, email, 'Ein Fahrzeug wurde für dich in MobiMory freigegeben',
      a.email + ' hat ein Fahrzeug für dich freigegeben (nur lesen), gültig von ' + ab + ' bis ' + b.bis + '.\n\nDein Code: ' + code + '\n\nMelde dich in MobiMory mit dieser E-Mail-Adresse an und trage den Code unter Funktionen › Freigaben ein. Er gilt ' + EINLADUNG_TAGE + ' Tage und nur einmal.\n\nWenn du die Einladung nicht erwartest, ignoriere diese E-Mail. Es passiert nichts.');
  } catch (e) {
    await db.prepare('DELETE FROM freigabe WHERE id = ?').bind(id).run();
    throw e;
  }
  return { ok: true, id, ab, bis: b.bis, einladungBis, codeGesendet: !!r.gesendet, entwicklungsCode: r.entwicklung ? code : undefined };
}

/* Der Gast nimmt mit dem Code an. Der Code gilt nur für die eingeladene E-Mail-Adresse und nur einmal. */
async function freigabeAnnehmen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  await bremsen(db, await schluesselFuer('fre-a', a.id), 10, 60 * MINUTE, jetzt, 'Zu viele Versuche mit dem Code.');
  const code = codeSauber(b.code, EINLADUNG_CODE_LAENGE);
  const fehler = new HttpFehler(400, 'Dieser Code gilt nicht (mehr) oder gehört zu einer anderen E-Mail-Adresse.', { feld: 'code' });
  if (!code) throw fehler;
  const f = await db.prepare('SELECT id, email FROM freigabe WHERE code_hash = ? AND angenommen_am IS NULL AND widerrufen_am IS NULL AND einladung_bis > ? AND laeuft_ab > ?')
    .bind(await codeAbdruck(env, 'freigabe', code), jetzt, jetzt).first();
  if (!f || f.email !== a.email) throw fehler;
  const r = await db.prepare('UPDATE freigabe SET gast_nutzer_id = ?, angenommen_am = ? WHERE id = ? AND angenommen_am IS NULL AND widerrufen_am IS NULL').bind(a.id, jetzt, f.id).run();
  if (!r.meta || r.meta.changes < 1) throw fehler;
  return { ok: true, id: f.id };
}

/* Widerruf durch den Besitzer oder Zurückgeben durch den Gast. Der Zugriff endet sofort. */
async function freigabeWiderrufen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  const id = kennung(b.id);
  const r = await db.prepare('UPDATE freigabe SET widerrufen_am = ? WHERE id = ? AND widerrufen_am IS NULL AND (datenraum_id = ? OR gast_nutzer_id = ?)').bind(jetzt, id, a.datenraumId || '', a.id).run();
  if (!r.meta || r.meta.changes < 1) throw new HttpFehler(404, 'Diese Freigabe gibt es nicht (mehr).');
  return { ok: true };
}

async function freigabeListe(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = a.datenraumId || '';
  const g = await db.prepare('SELECT f.id, f.fahrzeug_id, f.email, f.ab_am, f.laeuft_ab, f.einladung_bis, f.angenommen_am, f.widerrufen_am, ' + NAME_VON_FAHRZEUG + ' AS name FROM freigabe f WHERE f.datenraum_id = ? ORDER BY f.erstellt_am DESC LIMIT 200').bind(dr).all();
  const e = await db.prepare('SELECT f.id, f.fahrzeug_id, n.email AS von, f.ab_am, f.laeuft_ab, f.einladung_bis, f.angenommen_am, f.widerrufen_am, ' + NAME_VON_FAHRZEUG + ' AS name FROM freigabe f JOIN datenraum d ON d.id = f.datenraum_id JOIN nutzer n ON n.id = d.nutzer_id WHERE f.gast_nutzer_id = ? ORDER BY f.erstellt_am DESC LIMIT 200').bind(a.id).all();
  const k = await db.prepare('SELECT f.id, f.fahrzeug_id, f.laeuft_ab, f.widerrufen_am, ' + NAME_VON_FAHRZEUG + ' AS name FROM kontrolle f WHERE f.datenraum_id = ? ORDER BY f.erstellt_am DESC LIMIT 200').bind(dr).all();
  const tag = (ms) => datumText(ms);
  return {
    ok: true,
    gegeben: (g.results || []).map((f) => ({ id: f.id, fahrzeugId: f.fahrzeug_id, name: f.name || null, email: f.email, ab: tag(f.ab_am), bis: tag(f.laeuft_ab), status: freigabeStatus(f, jetzt) })),
    erhalten: (e.results || []).filter((f) => !f.widerrufen_am).map((f) => ({ id: f.id, fahrzeugId: f.fahrzeug_id, name: f.name || null, von: f.von, ab: tag(f.ab_am), bis: tag(f.laeuft_ab), status: freigabeStatus(f, jetzt) })),
    kontrollen: (k.results || []).map((f) => ({ id: f.id, fahrzeugId: f.fahrzeug_id, name: f.name || null, laeuftAb: f.laeuft_ab, status: f.widerrufen_am ? 'widerrufen' : (f.laeuft_ab <= jetzt ? 'abgelaufen' : 'aktiv') }))
  };
}

/* Die Freigabe, die dieses Konto gerade zum Lesen berechtigt. Alles andere ist 403, nie mehr Auskunft als nötig. */
async function gastFreigabe(db, a, id, jetzt) {
  const f = await db.prepare('SELECT id, datenraum_id, fahrzeug_id, gast_nutzer_id, ab_am, laeuft_ab, angenommen_am, widerrufen_am FROM freigabe WHERE id = ?').bind(kennung(id, 'freigabe')).first();
  if (!f || f.gast_nutzer_id !== a.id || !f.angenommen_am || f.widerrufen_am || f.ab_am > jetzt || f.laeuft_ab <= jetzt) throw new HttpFehler(403, 'Diese Freigabe gilt nicht (mehr).');
  return f;
}

const J = (feld) => "json_extract(x.nutzlast, '" + feld + "')";

/* Die Datensätze, die ein Gast zu einem Fahrzeug sieht. Der Dienst liefert sie in der Form des Abgleichs, die App baut daraus die Ansicht.
   gast: Fahrzeug, aktuelle Angaben, Fristen samt Erledigungen, Zähler, Dokumente samt Dateien, letztes Prüfergebnis.
   kontrolle: nur Fahrzeug, Dokumente samt Dateien und das letzte Prüfergebnis.
   Nie dabei: Kosten, Notizen, Nachweise, Reisechecks, Routen, Besuche, Ereignisse und Aktivitäten, Personen, Orte, GPS. */
async function fahrzeugSicht(db, dr, fz, umfang) {
  const k = [];
  const holen = async (sql, ...w) => { const r = await db.prepare(sql).bind(...w).all(); (r.results || []).forEach((x) => k.push({ tabelle: x.tabelle, id: x.objekt_id, nutzlast: x.nutzlast })); };
  const AUS = 'SELECT x.tabelle, x.objekt_id, x.nutzlast FROM abgleich x WHERE x.datenraum_id = ? AND x.geloescht = 0 AND ';
  const objekte = (tabelle) => "(SELECT objekt_id FROM abgleich WHERE datenraum_id = ? AND tabelle = '" + tabelle + "' AND fahrzeug_id = ? AND geloescht = 0)";
  const verlaufVon = (typ, tabelle) => AUS + "x.tabelle = 'verlaeufe' AND " + J('$.objektTyp') + " = '" + typ + "' AND " + J('$.objektId') + ' IN ' + objekte(tabelle);
  await holen(AUS + "x.tabelle = 'fahrzeuge' AND x.objekt_id = ?", dr, fz);
  if (!k.length) return null;
  await holen(AUS + "x.tabelle = 'eintraege' AND x.fahrzeug_id = ? ORDER BY " + J('$.nr') + ' DESC LIMIT 1', dr, fz);
  /* Dokumente und ihre Dateien (ohne den Inhalt, der liegt in R2) */
  await holen(AUS + "x.tabelle = 'dokumente' AND x.fahrzeug_id = ?", dr, fz);
  await holen(verlaufVon('dokument', 'dokumente'), dr, dr, fz);
  await holen(AUS + "x.tabelle = 'dateien' AND " + J('$.dokumentId') + ' IN ' + objekte('dokumente'), dr, dr, fz);
  /* Letztes Prüfergebnis: über die Aktivitäten dieses Fahrzeugs. */
  await holen(AUS + "x.tabelle = 'tagespruefungen' AND " + J('$.aktivitaetId') + " IN (SELECT json_extract(v.nutzlast, '$.objektId') FROM abgleich v WHERE v.datenraum_id = ? AND v.tabelle = 'verlaeufe' AND v.geloescht = 0 AND json_extract(v.nutzlast, '$.objektTyp') = 'aktivitaet' AND json_extract(v.nutzlast, '$.werte.fahrzeugId') = ?) ORDER BY " + J('$.erstelltAm') + ' DESC LIMIT 1', dr, dr, fz);
  if (umfang === 'gast') {
    await holen(AUS + "x.tabelle = 'fristen' AND x.fahrzeug_id = ?", dr, fz);
    await holen(verlaufVon('frist', 'fristen'), dr, dr, fz);
    await holen(AUS + "x.tabelle = 'durchfuehrungen' AND " + J('$.fristId') + ' IN ' + objekte('fristen') + ' ORDER BY ' + J('$.datum') + ' DESC LIMIT ' + SICHT_DURCHFUEHRUNGEN, dr, dr, fz);
    await holen(AUS + "x.tabelle = 'zaehler' AND x.fahrzeug_id = ?", dr, fz);
    await holen(verlaufVon('zaehler', 'zaehler'), dr, dr, fz);
    await holen(AUS + "x.tabelle = 'zaehlerstaende' AND " + J('$.zaehlerId') + ' IN ' + objekte('zaehler') + ' ORDER BY ' + J('$.datum') + ' DESC LIMIT ' + SICHT_STAENDE, dr, dr, fz);
  }
  return k;
}

async function geteiltFahrzeug(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const f = await gastFreigabe(db, a, new URL(request.url).searchParams.get('freigabe'), jetzt);
  const s = await fahrzeugSicht(db, f.datenraum_id, f.fahrzeug_id, 'gast');
  if (!s) throw new HttpFehler(404, 'Dieses Fahrzeug wird nicht mehr geteilt.');
  return { ok: true, fahrzeugId: f.fahrzeug_id, bis: datumText(f.laeuft_ab), datensaetze: s };
}

/* Datei zu einem Dokument des freigegebenen Fahrzeugs. Nachweis-Scans und Fotos sind nie erreichbar. */
async function dokumentDatei(env, db, dr, fz, dateiId) {
  const r2 = dateiSpeicher(env);
  const id = kennung(dateiId, 'id');
  const d = await db.prepare("SELECT x.nutzlast AS nutzlast FROM abgleich x WHERE x.datenraum_id = ? AND x.tabelle = 'dateien' AND x.objekt_id = ? AND x.geloescht = 0 AND json_extract(x.nutzlast, '$.dokumentId') IN (SELECT objekt_id FROM abgleich WHERE datenraum_id = ? AND tabelle = 'dokumente' AND fahrzeug_id = ? AND geloescht = 0)").bind(dr, id, dr, fz).first();
  if (!d) throw new HttpFehler(404, 'Diese Datei gibt es hier nicht.');
  const m = await db.prepare("SELECT groesse, verschluesselt FROM datei WHERE datenraum_id = ? AND tabelle = 'dateien' AND objekt_id = ?").bind(dr, id).first();
  if (!m || m.verschluesselt) throw new HttpFehler(404, 'Diese Datei liegt nicht beim Dienst.');
  const o = await r2.get(dateiPfad(dr, 'dateien', id));
  if (!o) throw new HttpFehler(404, 'Diese Datei liegt nicht beim Dienst.');
  return new Response(o.body, { status: 200, headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(m.groesse), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Verschluesselt': '0' } });
}

async function geteiltDatei(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const u = new URL(request.url);
  const f = await gastFreigabe(db, a, u.searchParams.get('freigabe'), jetzt);
  return dokumentDatei(env, db, f.datenraum_id, f.fahrzeug_id, u.searchParams.get('id'));
}

/* Kontroll-Freigabe: kurzer Code, nur Papiere und Prüfergebnis, ohne Konto des Kontrolleurs, nur kurz gültig. */
async function kontrolleErstellen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const b = await bodyLesen(request);
  const fz = kennung(b.fahrzeugId, 'fahrzeugId');
  const stunden = b.stunden === undefined || b.stunden === null ? KONTROLLE_STANDARD_STUNDEN : b.stunden;
  if (!Number.isInteger(stunden) || stunden < 1 || stunden > KONTROLLE_MAX_STUNDEN) throw new HttpFehler(400, 'Die Gültigkeit liegt zwischen 1 Stunde und ' + KONTROLLE_MAX_STUNDEN + ' Stunden (7 Tage).', { feld: 'stunden' });
  if (!(await fahrzeugDa(db, dr, fz))) throw new HttpFehler(404, 'Dieses Fahrzeug liegt nicht beim Dienst. Bitte zuerst unter Funktionen › Konto abgleichen.', { feld: 'fahrzeugId' });
  await bremsen(db, await schluesselFuer('kon-e', a.id), 20, 60 * MINUTE, jetzt, 'Du hast in kurzer Zeit zu viele Codes erzeugt.');
  const offen = await db.prepare('SELECT COUNT(*) AS n FROM kontrolle WHERE datenraum_id = ? AND widerrufen_am IS NULL AND laeuft_ab > ?').bind(dr, jetzt).first();
  if (offen && offen.n >= MAX_KONTROLLEN) throw new HttpFehler(409, 'Es gibt schon ' + MAX_KONTROLLEN + ' gültige Kontroll-Codes. Bitte widerrufe zuerst einen.');
  const code = zufallCode(KONTROLLE_CODE_LAENGE), id = crypto.randomUUID(), laeuftAb = jetzt + stunden * 60 * MINUTE;
  await db.prepare('INSERT INTO kontrolle (id, datenraum_id, fahrzeug_id, code_hash, erstellt_am, laeuft_ab) VALUES (?, ?, ?, ?, ?, ?)').bind(id, dr, fz, await codeAbdruck(env, 'kontrolle', code), jetzt, laeuftAb).run();
  return { ok: true, id, code, laeuftAb, stunden };
}

async function kontrolleWiderrufen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt), dr = raumVon(a);
  const b = await bodyLesen(request);
  const r = await db.prepare('UPDATE kontrolle SET widerrufen_am = ? WHERE id = ? AND datenraum_id = ? AND widerrufen_am IS NULL').bind(jetzt, kennung(b.id), dr).run();
  if (!r.meta || r.meta.changes < 1) throw new HttpFehler(404, 'Diesen Kontroll-Code gibt es nicht (mehr).');
  return { ok: true };
}

/* Ohne Anmeldung: Der Code ist der Schlüssel. Falsche Versuche werden je Adresse gebremst. */
async function kontrolleFinden(request, env, db, jetzt) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unbekannt';
  await bremsen(db, await schluesselFuer('kon-i', ip), 40, 15 * MINUTE, jetzt, 'Zu viele Versuche.');
  const code = codeSauber(new URL(request.url).searchParams.get('code'), KONTROLLE_CODE_LAENGE);
  const nein = new HttpFehler(404, 'Dieser Code gilt nicht (mehr).');
  if (!code) throw nein;
  const k = await db.prepare('SELECT id, datenraum_id, fahrzeug_id, laeuft_ab FROM kontrolle WHERE code_hash = ? AND widerrufen_am IS NULL AND laeuft_ab > ?').bind(await codeAbdruck(env, 'kontrolle', code), jetzt).first();
  if (!k) throw nein;
  return k;
}

async function kontrolleLesen(request, env, db, jetzt) {
  const k = await kontrolleFinden(request, env, db, jetzt);
  const s = await fahrzeugSicht(db, k.datenraum_id, k.fahrzeug_id, 'kontrolle');
  if (!s) throw new HttpFehler(404, 'Dieses Fahrzeug wird nicht mehr geteilt.');
  return { ok: true, fahrzeugId: k.fahrzeug_id, laeuftAb: k.laeuft_ab, datensaetze: s };
}

async function kontrolleDatei(request, env, db, jetzt) {
  const k = await kontrolleFinden(request, env, db, jetzt);
  return dokumentDatei(env, db, k.datenraum_id, k.fahrzeug_id, new URL(request.url).searchParams.get('id'));
}

/* Abgelaufene Freigaben und Codes bleiben 30 Tage sichtbar, dann verschwinden sie. Fehlen die Tabellen (13c noch nicht eingerichtet), ist nichts zu tun. */
async function freigabenAufraeumen(db, jetzt) {
  try {
    await db.batch([
      db.prepare('DELETE FROM freigabe WHERE laeuft_ab <= ? OR widerrufen_am <= ?').bind(jetzt - 30 * TAG, jetzt - 30 * TAG),
      db.prepare('DELETE FROM kontrolle WHERE laeuft_ab <= ? OR widerrufen_am <= ?').bind(jetzt - 30 * TAG, jetzt - 30 * TAG)
    ]);
  } catch (e) { if (!/no such table/i.test(String(e && e.message || e))) throw e; }
}

async function gesundheit(env) {
  let tabellen = false, abgleich = false, dateien = false, freigaben = false, stufen = false;
  try { await datenbank(env).prepare('SELECT 1 FROM nutzer LIMIT 1').first(); tabellen = true; } catch (e) { tabellen = false; }
  try { const db = datenbank(env); await db.prepare('SELECT 1 FROM abgleich_stand LIMIT 1').first(); await db.prepare('SELECT 1 FROM abgleich LIMIT 1').first(); await db.prepare('SELECT 1 FROM sicherung LIMIT 1').first(); await db.prepare('SELECT 1 FROM sicherungsteil LIMIT 1').first(); abgleich = true; } catch (e) { abgleich = false; }
  try { await datenbank(env).prepare('SELECT 1 FROM datei LIMIT 1').first(); dateien = true; } catch (e) { dateien = false; }
  try { const db = datenbank(env); await db.prepare('SELECT 1 FROM freigabe LIMIT 1').first(); await db.prepare('SELECT 1 FROM kontrolle LIMIT 1').first(); freigaben = true; } catch (e) { freigaben = false; }
  try { const db = datenbank(env); await db.prepare('SELECT 1 FROM stufe_konto LIMIT 1').first(); await db.prepare('SELECT 1 FROM testwoche LIMIT 1').first(); await db.prepare('SELECT 1 FROM check_nutzung LIMIT 1').first(); await db.prepare('SELECT 1 FROM check_ergebnis LIMIT 1').first(); stufen = true; } catch (e) { stufen = false; }
  let waechter = false;
  try { await datenbank(env).prepare('SELECT 1 FROM waechter_stand LIMIT 1').first(); waechter = !!(env && env.EMAIL && env.ABSENDER && waechterEmpfaenger(env)); } catch (e) { waechter = false; }
  return {
    ok: true, dienst: DIENST, version: VERSION,
    datenbank: !!(env && env.DB), tabellen, abgleich, dateien, freigaben, stufen, waechter,
    recherche: !!(env && typeof env.RECHERCHE_URL === 'string' && /^https:\/\//.test(env.RECHERCHE_URL) && typeof env.RECHERCHE_TOKEN === 'string' && env.RECHERCHE_TOKEN.length >= 8),
    pepper: typeof (env && env.PASSWORT_PEPPER) === 'string' && env.PASSWORT_PEPPER.length >= 32,
    mail: !!(env && env.EMAIL && env.ABSENDER),
    speicher: !!(env && env.DATEN),
    entwicklung: !!(env && env.ENTWICKLUNG === '1')
  };
}


/* ---------- 13e: Stufen, Kontingent und Online-Checks ---------- */

/* Die Zahlen sind Richtwerte (Nutzer, 12.11.2026). Sie stehen nur hier und in js/konto.js (ein Test vergleicht beide). */
export const STUFEN = {
  basic: { name: 'Basic', geraete: 2, checks: 0, fahrzeuge: 1, online: false },
  test: { name: 'Testwoche', geraete: 4, checks: 1, fahrzeuge: 3, online: true },
  mittel: { name: 'Mittel', geraete: 4, checks: 3, fahrzeuge: 3, online: true },
  voll: { name: 'Voll', geraete: 10, checks: 10, fahrzeuge: null, online: true },
  /* Nur für den Entwickler, nur per SQL setzbar, keine Grenzen (null = unbegrenzt). Nur die Bremse gegen zu viele Checks hintereinander bleibt. */
  entwickler: { name: 'Entwickler', geraete: null, checks: null, fahrzeuge: null, online: true }
};
export const TESTWOCHE_TAGE = 7;
export const CHECK_ZEITRAUM_TAGE = 365;
const MAX_CHECK_BODY = 256 * 1024;
const MAX_CHECK_ERGEBNIS = 500 * 1024;
const CHECK_ARTEN = ['reise', 'tag', 'grund'];
const ZEIT_RECHERCHE_MS = 170 * 1000;

function fehltTabelle(e) { return /no such table/i.test(String(e && e.message || e)); }

/* Die Stufe eines Nutzers: bezahlt (Mittel oder Voll, gültig), sonst Testwoche, sonst Basic. Fehlen die Tabellen und ist „nachsichtig“ gesetzt
   (beim Anmelden), gibt es keine Grenze, damit sich vor dem Einrichten der Tabellen niemand aussperrt. */
async function stufeVon(db, nutzerId, jetzt, nachsichtig) {
  try {
    const z = await db.prepare('SELECT stufe, gueltig_bis FROM stufe_konto WHERE nutzer_id = ?').bind(nutzerId).first();
    if (z && STUFEN[z.stufe] && (z.stufe === 'mittel' || z.stufe === 'voll' || z.stufe === 'entwickler') && (z.gueltig_bis === null || z.gueltig_bis === undefined || z.gueltig_bis > jetzt)) {
      return { id: z.stufe, name: STUFEN[z.stufe].name, grenzen: STUFEN[z.stufe], bis: z.gueltig_bis === undefined ? null : z.gueltig_bis };
    }
    const t = await db.prepare('SELECT ende_am FROM testwoche WHERE nutzer_id = ? AND ende_am > ?').bind(nutzerId, jetzt).first();
    if (t) return { id: 'test', name: STUFEN.test.name, grenzen: STUFEN.test, bis: t.ende_am };
    return { id: 'basic', name: STUFEN.basic.name, grenzen: STUFEN.basic, bis: null };
  } catch (e) {
    if (fehltTabelle(e)) { if (nachsichtig) return null; throw e; }
    throw e;
  }
}

async function testwocheStarten(db, env, nutzerId, email, jetzt) {
  try {
    const h = zuHex(await hmac(pepper(env), 'testwoche:' + email));
    await db.prepare('INSERT INTO testwoche (email_hash, nutzer_id, start_am, ende_am) VALUES (?, ?, ?, ?) ON CONFLICT(email_hash) DO UPDATE SET nutzer_id = excluded.nutzer_id')
      .bind(h, nutzerId, jetzt, jetzt + TESTWOCHE_TAGE * TAG).run();
  } catch (e) { if (!fehltTabelle(e)) throw e; }
}

async function checksAufraeumen(db, jetzt) {
  try {
    await db.batch([
      db.prepare('DELETE FROM check_nutzung WHERE am <= ?').bind(jetzt - (CHECK_ZEITRAUM_TAGE + 35) * TAG),
      db.prepare('DELETE FROM check_nutzung WHERE status = ? AND am <= ?').bind('laeuft', jetzt - 1 * TAG),
      db.prepare('DELETE FROM check_ergebnis WHERE erstellt_am <= ?').bind(jetzt - 2 * CHECK_ZEITRAUM_TAGE * TAG)
    ]);
  } catch (e) { if (!fehltTabelle(e)) throw e; }
}

/* Wie viele Online-Checks zählen gegen die Grenze: bei der Testwoche nur die der Testwoche, bei bezahlten Stufen nur die bezahlten. */
async function checksGenutzt(db, dr, stufeId, jetzt) {
  const klasse = stufeId === 'test' ? ['test'] : (stufeId === 'entwickler' ? ['entwickler'] : ['mittel', 'voll']);
  const z = await db.prepare('SELECT COUNT(*) AS n FROM check_nutzung WHERE datenraum_id = ? AND am > ? AND status IN (?, ?) AND stufe IN (?, ?)')
    .bind(dr, jetzt - CHECK_ZEITRAUM_TAGE * TAG, 'laeuft', 'ok', klasse[0], klasse[1] || klasse[0]).first();
  return z ? z.n : 0;
}

async function kontoStufe(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const st = await stufeVon(db, a.id, jetzt, false);
  const g = st.grenzen;
  const geraete = await db.prepare('SELECT COUNT(*) AS n FROM sitzung WHERE nutzer_id = ? AND laeuft_ab > ?').bind(a.id, jetzt).first();
  const genutzt = a.datenraumId && g.online ? await checksGenutzt(db, a.datenraumId, st.id, jetzt) : 0;
  return {
    ok: true,
    stufe: { id: st.id, name: st.name, bis: st.bis },
    grenzen: { geraete: g.geraete, checks: g.checks, fahrzeuge: g.fahrzeuge, online: g.online },
    nutzung: { geraete: geraete ? geraete.n : 0, checks: genutzt, checksFrei: g.checks === null ? null : Math.max(0, g.checks - genutzt), zeitraumTage: CHECK_ZEITRAUM_TAGE }
  };
}

function stabilText(x) {
  if (x === null || typeof x !== 'object') return JSON.stringify(x === undefined ? null : x);
  if (Array.isArray(x)) return '[' + x.map(stabilText).join(',') + ']';
  return '{' + Object.keys(x).sort().map((k) => JSON.stringify(k) + ':' + stabilText(x[k])).join(',') + '}';
}

/* Ein Online-Check: Anmeldung, Stufe und Kontingent prüfen, zählen, an den Recherche-Dienst weiterreichen, Ergebnis speichern.
   Schlägt die Recherche fehl, wird der Check nicht gezählt. Ein gespeicherter Check (quelle „gespeichert“) zählt nie. */
async function checkSenden(request, env, db, jetzt, optionen) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request, MAX_CHECK_BODY);
  const art = typeof b.art === 'string' ? b.art : '';
  if (!CHECK_ARTEN.includes(art)) throw new HttpFehler(400, 'Die Art des Checks fehlt oder ist unbekannt.', { feld: 'art' });
  if (!b.anfrage || typeof b.anfrage !== 'object' || Array.isArray(b.anfrage)) throw new HttpFehler(400, 'Die Anfrage fehlt.', { feld: 'anfrage' });
  const quelle = b.quelle === 'gespeichert' ? 'gespeichert' : 'frisch';
  if (!a.datenraumId) throw new HttpFehler(400, 'Zu diesem Konto gehört noch kein Datenraum.');
  const st = await stufeVon(db, a.id, jetzt, false);
  if (!st.grenzen.online) {
    throw new HttpFehler(402, 'Online-Checks gibt es ab der Stufe Mittel. Deine Stufe ist ' + st.name + '.', { stufe: st.id });
  }
  const schluessel = await sha256Hex(art + ':' + stabilText(b.anfrage));

  if (quelle === 'gespeichert') {
    const g = await db.prepare('SELECT antwort, erstellt_am FROM check_ergebnis WHERE schluessel = ?').bind(schluessel).first();
    if (!g) throw new HttpFehler(404, 'Dazu gibt es noch keinen gespeicherten Check. Ein frischer Check zählt zu deinem Kontingent.', { gespeichert: false });
    let antwort;
    try { antwort = JSON.parse(g.antwort); } catch (e) { throw new HttpFehler(404, 'Der gespeicherte Check ist nicht lesbar. Mach einen frischen Check.'); }
    return { ok: true, gespeichert: true, stand: g.erstellt_am, hinweis: 'Gespeicherter Check vom ' + datumText(g.erstellt_am) + '. Er kann veraltet sein, eine Aktualisierung ist nicht garantiert.', antwort };
  }

  const url = env && typeof env.RECHERCHE_URL === 'string' ? env.RECHERCHE_URL.trim().replace(/\/+$/, '') : '';
  const token = env && typeof env.RECHERCHE_TOKEN === 'string' ? env.RECHERCHE_TOKEN : '';
  if (!/^https:\/\//.test(url) || token.length < 8) throw new HttpFehler(503, 'Der Recherche-Dienst ist im Konto-Dienst noch nicht eingetragen.');

  await bremsen(db, await schluesselFuer('chk', a.datenraumId), 8, 10 * MINUTE, jetzt, 'Es wurden zu viele Checks hintereinander gestartet.');
  const genutzt = await checksGenutzt(db, a.datenraumId, st.id, jetzt);
  if (st.grenzen.checks !== null && genutzt >= st.grenzen.checks) {
    throw new HttpFehler(402, 'Dein Kontingent ist aufgebraucht: ' + genutzt + ' von ' + st.grenzen.checks + ' Online-Checks in den letzten 12 Monaten. Ein gespeicherter Check zählt nicht.', { genutzt, grenze: st.grenzen.checks, stufe: st.id });
  }
  const nid = crypto.randomUUID();
  await db.prepare('INSERT INTO check_nutzung (id, datenraum_id, art, stufe, am, status) VALUES (?, ?, ?, ?, ?, ?)').bind(nid, a.datenraumId, art, st.id, jetzt, 'laeuft').run();
  async function zurueck() { try { await db.prepare('DELETE FROM check_nutzung WHERE id = ?').bind(nid).run(); } catch (e) { /* wird später aufgeräumt */ } }

  const holen = (optionen && optionen.fetch) || fetch;
  let r, text;
  try {
    const ctl = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), ZEIT_RECHERCHE_MS) : null;
    try {
      /* Der Recherche-Dienst lässt nur bekannte App-Adressen (ALLOWED_ORIGINS) durch. Der Konto-Dienst meldet sich mit der ersten erlaubten Adresse der App. */
      const kopf = { 'Content-Type': 'application/json', 'X-Mobimory-Token': token };
      const ur = erlaubteUrspruenge(env)[0];
      if (ur) kopf.Origin = ur;
      r = await holen(url + '/research', { method: 'POST', headers: kopf, body: JSON.stringify(b.anfrage), signal: ctl ? ctl.signal : undefined });
      text = await r.text();
    } finally { if (timer) clearTimeout(timer); }
  } catch (e) {
    await zurueck();
    throw new HttpFehler(502, 'Der Recherche-Dienst hat nicht rechtzeitig geantwortet. Dieser Check wurde nicht gezählt.');
  }
  let antwort = null;
  try { antwort = JSON.parse(text); } catch (e) { antwort = null; }
  if (!r.ok || !antwort || typeof antwort !== 'object') {
    await zurueck();
    const m = antwort && typeof antwort.error === 'string' ? antwort.error.slice(0, 300) : '';
    throw new HttpFehler(502, 'Der Recherche-Dienst konnte den Check nicht ausführen' + (m ? ': ' + m : '.') + ' Dieser Check wurde nicht gezählt.');
  }
  await db.prepare('UPDATE check_nutzung SET status = ? WHERE id = ?').bind('ok', nid).run();
  const roh = JSON.stringify(antwort);
  if (roh.length <= MAX_CHECK_ERGEBNIS) {
    await db.prepare('INSERT INTO check_ergebnis (schluessel, art, antwort, erstellt_am) VALUES (?, ?, ?, ?) ON CONFLICT(schluessel) DO UPDATE SET antwort = excluded.antwort, erstellt_am = excluded.erstellt_am').bind(schluessel, art, roh, jetzt).run();
  }
  return { ok: true, gespeichert: false, antwort, kontingent: { genutzt: genutzt + 1, grenze: st.grenzen.checks, stufe: st.id } };
}

/* ---------- Anfrage → Antwort ---------- */

function erlaubteUrspruenge(env) {
  return String((env && env.ERLAUBTE_URSPRUENGE) || '').split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean);
}

function antwort(status, obj, cors) {
  const kopf = Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  }, cors || {});
  return new Response(JSON.stringify(obj), { status, headers: kopf });
}

export async function behandeln(request, env, optionen) {
  const jetzt = optionen && typeof optionen.jetzt === 'function' ? optionen.jetzt() : Date.now();
  const url = new URL(request.url);
  const ursprung = request.headers.get('Origin');
  let cors = null;
  if (ursprung) {
    /* Die Ablehnung trägt die Kopfzeile für diese Adresse, damit die App „abgelehnt“ von „keine Verbindung“ unterscheiden kann. Sie enthält nur den Fehlertext. */
    if (!erlaubteUrspruenge(env).includes(ursprung)) return antwort(403, { ok: false, error: 'Diese App-Adresse ist beim Dienst nicht erlaubt.' }, { 'Access-Control-Allow-Origin': ursprung, 'Vary': 'Origin' });
    cors = { 'Access-Control-Allow-Origin': ursprung, 'Vary': 'Origin', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS', 'Access-Control-Expose-Headers': 'X-Verschluesselt', 'Access-Control-Max-Age': '600' };
  }
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors || {} });

  try {
    const weg = request.method + ' ' + url.pathname.replace(/\/+$/, '');
    if (weg === 'GET /gesundheit') return antwort(200, await gesundheit(env), cors);
    const wege = {
      'POST /konto/registrieren': registrieren,
      'POST /konto/code-anfordern': codeAnfordern,
      'POST /konto/code-pruefen': codePruefen,
      'POST /konto/anmelden': anmelden,
      'GET /konto/ich': ich,
      'POST /konto/passwort-setzen': passwortSetzen,
      'POST /konto/abmelden': abmelden,
      'POST /konto/loeschen': loeschen,
      'GET /abgleich/stand': abgleichStandWeg,
      'GET /abgleich/aenderungen': abgleichAenderungen,
      'POST /abgleich/senden': abgleichSenden,
      'POST /abgleich/leeren': abgleichLeeren,
      'POST /sicherung/anfangen': sicherungAnfangen,
      'POST /sicherung/teil': sicherungTeil,
      'POST /sicherung/fertig': sicherungFertig,
      'GET /sicherung/liste': sicherungListe,
      'GET /sicherung/teil': sicherungHolen,
      'POST /sicherung/loeschen': sicherungLoeschen,
      'PUT /datei': dateiHochladen,
      'GET /datei': dateiHolen,
      'GET /datei/liste': dateiListe,
      'POST /datei/loeschen': dateiLoeschenWeg,
      'POST /freigabe/einladen': freigabeEinladen,
      'POST /freigabe/annehmen': freigabeAnnehmen,
      'POST /freigabe/widerrufen': freigabeWiderrufen,
      'GET /freigabe/liste': freigabeListe,
      'GET /geteilt/fahrzeug': geteiltFahrzeug,
      'GET /geteilt/datei': geteiltDatei,
      'POST /kontrolle/erstellen': kontrolleErstellen,
      'POST /kontrolle/widerrufen': kontrolleWiderrufen,
      'GET /kontrolle/lesen': kontrolleLesen,
      'GET /kontrolle/datei': kontrolleDatei,
      'GET /konto/stufe': kontoStufe,
      'POST /check/senden': checkSenden
    };
    const f = wege[weg];
    if (!f) return antwort(404, { ok: false, error: 'Diese Adresse gibt es beim Dienst nicht.' }, cors);
    const db = datenbank(env);
    if (weg.startsWith('POST /konto/') && weg !== 'POST /konto/abmelden') await aufraeumen(db, jetzt);
    const erg = await f(request, env, db, jetzt, optionen);
    if (erg instanceof Response) { if (cors) Object.keys(cors).forEach((k) => erg.headers.set(k, cors[k])); return erg; }
    return antwort(200, erg, cors);
  } catch (e) {
    if (e instanceof HttpFehler) return antwort(e.status, Object.assign({ ok: false, error: e.message }, e.extra), cors);
    if (e && /no such table/i.test(String(e.message || e))) return antwort(503, { ok: false, error: 'Im Dienst fehlen Tabellen in der Datenbank. Die SQL-Zeilen der Einrichtung (Schritt 13b, 13d, 13c und 13e) müssen noch ausgeführt werden.' }, cors);
    return antwort(500, { ok: false, error: 'Im Dienst ist ein Fehler aufgetreten.' }, cors);
  }
}

/* ---------- 13e-3: Kosten-Wächter für die Testwochen (seit 2.0.71) ---------- */

/* Standardwerte (Nutzer, 12.11.2026). Alles lässt sich als Variable im Konto-Worker ändern, ohne neue Version:
     KOSTEN_CHECK            Kosten eines Online-Checks in Euro (Standard 0,45; nur eine Schätzung, der echte Wert kommt aus der OpenAI-Abrechnung)
     PREIS_MITTEL, PREIS_VOLL   Preis je Monat in Euro (Standard 5 und 10, Richtwerte)
     WAECHTER_ANTEIL         Warnung, wenn die Testwochen-Kosten diesen Anteil der Einnahmen überschreiten (Standard 0,2 = 20 %)
     WAECHTER_TAGE           Zeitraum für die Rechnung in Tagen (Standard 30)
     WAECHTER_CHECKS_TAG     Solange es keine Einnahmen gibt: höchstens so viele Testwochen-Checks in 24 Stunden (Standard 10)
     WAECHTER_TESTWOCHEN_TAG Höchstens so viele neue Testwochen in 24 Stunden (Standard 5)
     WAECHTER_EMAIL          Empfänger der Warnung (ohne sie wird nur geprüft und ins Protokoll geschrieben)
     WAECHTER_AUSGENOMMEN    Mail-Adressen, durch Komma getrennt, die nicht mitzählen: eigene Test-Konten und geschenkte Voll-Konten
   Das Konto mit der Stufe „entwickler“ zählt nie mit. */
export const WAECHTER_STANDARD = { kostenCheck: 0.45, preisMittel: 5, preisVoll: 10, anteil: 0.2, tage: 30, checksTag: 10, testwochenTag: 5 };
const WAECHTER_MAIL_ABSTAND = 60 * MINUTE;

function zahlVariable(env, name, standard, min, max) {
  const roh = env && env[name];
  if (roh === undefined || roh === null || String(roh).trim() === '') return standard;
  const z = Number(String(roh).trim().replace(',', '.'));
  if (!Number.isFinite(z) || z < min || z > max) return standard;
  return z;
}

function waechterEmpfaenger(env) {
  const e = env && typeof env.WAECHTER_EMAIL === 'string' ? env.WAECHTER_EMAIL.trim() : '';
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) ? e : '';
}

function waechterAusgenommen(env) {
  const roh = env && typeof env.WAECHTER_AUSGENOMMEN === 'string' ? env.WAECHTER_AUSGENOMMEN : '';
  return roh.split(',').map((x) => x.trim().toLowerCase()).filter((x) => x.length > 0 && x.length < 255).slice(0, 50);
}

function euroText(x) { return (Math.round(x * 100) / 100).toFixed(2).replace('.', ',') + ' €'; }
function prozentText(x) { return (Math.round(x * 1000) / 10).toString().replace('.', ',') + ' %'; }

/* Rechnet die Werte aus der Datenbank. Gibt null zurück, wenn die nötigen Tabellen fehlen. */
export async function waechterWerte(env, db, jetzt) {
  const k = {
    kostenCheck: zahlVariable(env, 'KOSTEN_CHECK', WAECHTER_STANDARD.kostenCheck, 0, 1000),
    preisMittel: zahlVariable(env, 'PREIS_MITTEL', WAECHTER_STANDARD.preisMittel, 0, 100000),
    preisVoll: zahlVariable(env, 'PREIS_VOLL', WAECHTER_STANDARD.preisVoll, 0, 100000),
    anteil: zahlVariable(env, 'WAECHTER_ANTEIL', WAECHTER_STANDARD.anteil, 0.001, 1000),
    tage: Math.round(zahlVariable(env, 'WAECHTER_TAGE', WAECHTER_STANDARD.tage, 1, 365)),
    checksTag: zahlVariable(env, 'WAECHTER_CHECKS_TAG', WAECHTER_STANDARD.checksTag, 0, 1000000),
    testwochenTag: zahlVariable(env, 'WAECHTER_TESTWOCHEN_TAG', WAECHTER_STANDARD.testwochenTag, 0, 1000000)
  };
  const kostenCheckGesetzt = !!(env && env.KOSTEN_CHECK !== undefined && String(env.KOSTEN_CHECK).trim() !== '' && k.kostenCheck === Number(String(env.KOSTEN_CHECK).trim().replace(',', '.')));
  const aus = waechterAusgenommen(env);
  const platz = aus.map(() => '?').join(',');
  /* Nutzer, die nicht mitzählen: das Entwickler-Konto und die ausgenommenen Adressen. */
  const ausNutzer = "SELECT nutzer_id FROM stufe_konto WHERE stufe = 'entwickler'" + (aus.length ? ' UNION SELECT id FROM nutzer WHERE lower(email) IN (' + platz + ')' : '');
  const ausRaeume = 'SELECT id FROM datenraum WHERE nutzer_id IN (' + ausNutzer + ')';
  try {
    const von = jetzt - k.tage * TAG, tag = jetzt - TAG;
    const c = await db.prepare("SELECT COUNT(*) AS n FROM check_nutzung WHERE stufe = 'test' AND status IN ('laeuft', 'ok') AND am > ? AND datenraum_id NOT IN (" + ausRaeume + ')')
      .bind(von, ...aus).first();
    const c24 = await db.prepare("SELECT COUNT(*) AS n FROM check_nutzung WHERE stufe = 'test' AND status IN ('laeuft', 'ok') AND am > ? AND datenraum_id NOT IN (" + ausRaeume + ')')
      .bind(tag, ...aus).first();
    const tw24 = await db.prepare('SELECT COUNT(*) AS n FROM testwoche WHERE start_am > ? AND nutzer_id NOT IN (' + ausNutzer + ')')
      .bind(tag, ...aus).first();
    const bezahlt = await db.prepare("SELECT stufe, COUNT(*) AS n FROM stufe_konto WHERE stufe IN ('mittel', 'voll') AND (gueltig_bis IS NULL OR gueltig_bis > ?) AND nutzer_id NOT IN (" + ausNutzer + ') GROUP BY stufe')
      .bind(jetzt, ...aus).all();
    let mittel = 0, voll = 0;
    for (const r of (bezahlt.results || [])) { if (r.stufe === 'mittel') mittel = r.n; else if (r.stufe === 'voll') voll = r.n; }
    const testChecks = c ? c.n : 0;
    const kosten = testChecks * k.kostenCheck;
    const einnahmenMonat = mittel * k.preisMittel + voll * k.preisVoll;
    const einnahmenZeitraum = einnahmenMonat * (k.tage / 30);
    return {
      einstellungen: k, kostenCheckGesetzt, von, bis: jetzt,
      testChecks, testChecks24: c24 ? c24.n : 0, neueTestwochen24: tw24 ? tw24.n : 0,
      kontenMittel: mittel, kontenVoll: voll, kosten, einnahmenMonat, einnahmenZeitraum,
      anteil: einnahmenZeitraum > 0 ? kosten / einnahmenZeitraum : null
    };
  } catch (e) {
    if (fehltTabelle(e)) return null;
    throw e;
  }
}

/* Welche Regeln schlagen an? Solange es keine Einnahmen gibt, gelten feste Obergrenzen, sonst der Anteil der Kosten an den Einnahmen.
   Die neuen Testwochen pro Tag gelten immer (ein plötzlicher Sprung deutet auf Missbrauch). */
export function waechterGruende(w) {
  const k = w.einstellungen, gruende = [];
  if (w.einnahmenMonat > 0) {
    if (w.anteil !== null && w.anteil > k.anteil) gruende.push('kosten-anteil');
  } else if (w.testChecks24 > k.checksTag) {
    gruende.push('checks-tag');
  }
  if (w.neueTestwochen24 > k.testwochenTag) gruende.push('testwochen-tag');
  return gruende;
}

function waechterText(w, gruende) {
  const k = w.einstellungen, z = [];
  z.push('Der Kosten-Wächter von MobiMory meldet auffällige Werte bei den Testwochen.');
  z.push('Zeitraum der Rechnung: ' + datumText(w.von) + ' bis ' + datumText(w.bis) + ' (' + k.tage + ' Tage). Stand: ' + new Date(w.bis).toISOString().slice(0, 16).replace('T', ' ') + ' UTC.');
  const zeilen = [];
  if (gruende.includes('kosten-anteil')) zeilen.push('- Die Kosten der Testwochen liegen bei ' + prozentText(w.anteil) + ' der Einnahmen (Schwelle ' + prozentText(k.anteil) + ').');
  if (gruende.includes('checks-tag')) zeilen.push('- Es gibt noch keine Einnahmen, und in den letzten 24 Stunden gab es ' + w.testChecks24 + ' Testwochen-Checks (Obergrenze ' + k.checksTag + ').');
  if (gruende.includes('testwochen-tag')) zeilen.push('- In den letzten 24 Stunden haben ' + w.neueTestwochen24 + ' neue Testwochen begonnen (Obergrenze ' + k.testwochenTag + ').');
  z.push('Ausgelöst durch:\n' + zeilen.join('\n'));
  z.push('Zahlen:\n'
    + '- Testwochen-Checks im Zeitraum: ' + w.testChecks + ', davon in den letzten 24 Stunden: ' + w.testChecks24 + '\n'
    + '- Neue Testwochen in den letzten 24 Stunden: ' + w.neueTestwochen24 + '\n'
    + '- Kosten der Testwochen im Zeitraum: ' + euroText(w.kosten) + ' (' + euroText(k.kostenCheck) + ' je Check' + (w.kostenCheckGesetzt ? '' : ', Schätzwert, die Variable KOSTEN_CHECK ist nicht gesetzt') + ')\n'
    + '- Bezahlte Konten: ' + w.kontenMittel + ' Mittel, ' + w.kontenVoll + ' Voll\n'
    + '- Einnahmen (gerechnet aus den Konten und den Preisen, keine gemessene Zahl): ' + euroText(w.einnahmenZeitraum) + ' im Zeitraum');
  z.push('Eine weitere Mail kommt frühestens in einer Stunde, falls die Werte bleiben. Die Schwellen und Preise stehen als Variablen im Konto-Worker.');
  return z.join('\n\n');
}

/* Eine Prüfrunde. Sie läuft alle 15 Minuten (Cron-Auslöser) und ändert nichts an Konten oder Stufen.
   Ergebnis: { geprueft, warnung, gruende, mail, werte } mit mail = 'gesendet', 'gedrosselt', 'kein-empfaenger', 'fehlgeschlagen' oder 'keine'. */
export async function waechterPruefen(env, db, jetzt) {
  const w = await waechterWerte(env, db, jetzt);
  if (!w) return { geprueft: false, warnung: false, gruende: [], mail: 'keine', werte: null };
  const gruende = waechterGruende(w);
  if (!gruende.length) return { geprueft: true, warnung: false, gruende, mail: 'keine', werte: w };
  const an = waechterEmpfaenger(env);
  if (!an) return { geprueft: true, warnung: true, gruende, mail: 'kein-empfaenger', werte: w };
  let alt = null;
  try {
    const z = await db.prepare('SELECT wert FROM waechter_stand WHERE schluessel = ?').bind('letzte_mail').first();
    alt = z ? z.wert : null;
  } catch (e) {
    /* Ohne die Tabelle gäbe es keine Bremse (alle 15 Minuten eine Mail), also wird nichts gesendet. */
    if (fehltTabelle(e)) return { geprueft: true, warnung: true, gruende, mail: 'fehlgeschlagen', werte: w };
    throw e;
  }
  if (alt !== null && jetzt - alt < WAECHTER_MAIL_ABSTAND) return { geprueft: true, warnung: true, gruende, mail: 'gedrosselt', werte: w };
  /* Erst die Zeit eintragen, dann senden: Schlägt das Senden fehl, wird der alte Wert zurückgesetzt. */
  await db.prepare('INSERT OR REPLACE INTO waechter_stand (schluessel, wert) VALUES (?, ?)').bind('letzte_mail', jetzt).run();
  try {
    await mailSenden(env, an, 'MobiMory Kosten-Wächter: Warnung', waechterText(w, gruende));
  } catch (e) {
    try {
      if (alt === null) await db.prepare('DELETE FROM waechter_stand WHERE schluessel = ?').bind('letzte_mail').run();
      else await db.prepare('INSERT OR REPLACE INTO waechter_stand (schluessel, wert) VALUES (?, ?)').bind('letzte_mail', alt).run();
    } catch (e2) { /* nächster Lauf */ }
    return { geprueft: true, warnung: true, gruende, mail: 'fehlgeschlagen', werte: w };
  }
  return { geprueft: true, warnung: true, gruende, mail: 'gesendet', werte: w };
}

export default {
  fetch(request, env) { return behandeln(request, env); },
  /* Cron-Auslöser (wrangler-konto.jsonc, alle 15 Minuten): der Kosten-Wächter. Fehler stören nichts anderes, sie stehen im Protokoll. */
  scheduled(event, env, ctx) {
    const lauf = waechterPruefen(env, datenbank(env), Date.now()).then((r) => {
      console.log('Kosten-Wächter: geprüft=' + r.geprueft + ' Warnung=' + r.warnung + ' Gründe=' + r.gruende.join(',') + ' Mail=' + r.mail);
    }).catch((e) => { console.log('Kosten-Wächter: Fehler ' + String(e && e.message || e)); });
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(lauf);
    return lauf;
  }
};
