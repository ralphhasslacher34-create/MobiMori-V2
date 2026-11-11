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
 * Die Rechte an einzelnen Fahrzeugen und Freigaben folgen in 13c.
 */

export const DIENST = 'mobimory-konto';
export const VERSION = '13b-1';

/* Die Laufzeit von Cloudflare lehnt mehr als 100 000 Runden ab. Die Zahl steht im gespeicherten Wert, sie lässt sich später erhöhen. */
export const PBKDF2_RUNDEN = 100000;
const SITZUNG_TAGE = 90;
const SITZUNG_ERNEUERN_TAGE = 30;
const CODE_MINUTEN = 10;
const CODE_VERSUCHE = 5;
const MAX_BODY = 4096;
const MIN_PASSWORT = 10;
const MAX_PASSWORT_BYTES = 200;
const MAX_ABGLEICH_BODY = 1024 * 1024;
const MAX_ABGLEICH_NUTZLAST = 48 * 1024;
const MAX_PAKET = 40;
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

  let n = await db.prepare('SELECT id, passwort_wartend FROM nutzer WHERE email = ?').bind(email).first();
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

/* Löscht das Konto samt Datenraum und allen Sitzungen. Was später auf dem Server liegt (Dokumente in R2), wird in 13d mit gelöscht. */
async function loeschen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  if (b.bestaetigung !== 'LÖSCHEN') throw new HttpFehler(400, 'Zum Löschen muss das Wort LÖSCHEN eingegeben werden.', { feld: 'bestaetigung' });
  if (a.datenraumId) { try { await datenraumLeeren(db, a.datenraumId, true); } catch (e) { /* Tabellen von 13b noch nicht angelegt: nichts zu löschen */ } }
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
  'tagespruefungen', 'personen', 'tiere', 'adressen', 'orte', 'gebiete', 'regeln', 'verlaeufe'];
export const ABGLEICH_VERLAUF_TYPEN = ['zaehler', 'frist', 'vorgang', 'aktivitaet', 'besatzung', 'verantwortung', 'tagesabschnitt', 'ereignis', 'aktivitaetsart',
  'ereignisart', 'ort', 'gebiet', 'regel', 'person', 'tier', 'adresse'];
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
async function datenraumLeeren(db, dr, ganz) {
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
  await datenraumLeeren(db, dr, false);
  return { ok: true };
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

async function gesundheit(env) {
  let tabellen = false, abgleich = false;
  try { await datenbank(env).prepare('SELECT 1 FROM nutzer LIMIT 1').first(); tabellen = true; } catch (e) { tabellen = false; }
  try { const db = datenbank(env); await db.prepare('SELECT 1 FROM abgleich_stand LIMIT 1').first(); await db.prepare('SELECT 1 FROM abgleich LIMIT 1').first(); await db.prepare('SELECT 1 FROM sicherung LIMIT 1').first(); await db.prepare('SELECT 1 FROM sicherungsteil LIMIT 1').first(); abgleich = true; } catch (e) { abgleich = false; }
  return {
    ok: true, dienst: DIENST, version: VERSION,
    datenbank: !!(env && env.DB), tabellen, abgleich,
    pepper: typeof (env && env.PASSWORT_PEPPER) === 'string' && env.PASSWORT_PEPPER.length >= 32,
    mail: !!(env && env.EMAIL && env.ABSENDER),
    speicher: !!(env && env.DATEN),
    entwicklung: !!(env && env.ENTWICKLUNG === '1')
  };
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
    cors = { 'Access-Control-Allow-Origin': ursprung, 'Vary': 'Origin', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Max-Age': '600' };
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
      'POST /sicherung/loeschen': sicherungLoeschen
    };
    const f = wege[weg];
    if (!f) return antwort(404, { ok: false, error: 'Diese Adresse gibt es beim Dienst nicht.' }, cors);
    const db = datenbank(env);
    if (weg.startsWith('POST /konto/') && weg !== 'POST /konto/abmelden') await aufraeumen(db, jetzt);
    return antwort(200, await f(request, env, db, jetzt), cors);
  } catch (e) {
    if (e instanceof HttpFehler) return antwort(e.status, Object.assign({ ok: false, error: e.message }, e.extra), cors);
    if (e && /no such table/i.test(String(e.message || e))) return antwort(503, { ok: false, error: 'Im Dienst fehlen Tabellen in der Datenbank. Die SQL-Zeilen der Einrichtung (Schritt 13b) müssen noch ausgeführt werden.' }, cors);
    return antwort(500, { ok: false, error: 'Im Dienst ist ein Fehler aufgetreten.' }, cors);
  }
}

export default {
  fetch(request, env) { return behandeln(request, env); }
};
