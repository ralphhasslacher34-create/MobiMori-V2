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
 * 13h: Alarm-Nachrichten (Push und E-Mail) an die angemeldeten Geräte, Tabelle push_ziel (seit 2.0.120)
 * 13g: Lesedienst für Smart Capture (Google Cloud Vision, EU-Adresse): Foto rein, Text mit Positionen raus, nichts gespeichert, nur gezählt (Tabelle lese_nutzung).
 *      Secret GOOGLE_VISION_KEY im Worker.
 * 13e: Stufen (Basic, Testwoche, Mittel, Voll, Entwickler ohne Grenzen) mit Grenzen für Geräte und Online-Checks. Die Online-Checks gehen über diesen Dienst: Er prüft Anmeldung,
 *      Stufe und Kontingent, zählt, reicht die Anfrage an den Recherche-Dienst weiter und speichert das Ergebnis (Check-Datenbank). Eine Testwoche je
 *      bestätigter E-Mail-Adresse. Vier weitere Tabellen (schema.sql, ab „13e“). Nötig dafür: Variable RECHERCHE_URL und Geheimnis RECHERCHE_TOKEN.
 * 13e-3 (seit 2.0.71): Kosten-Wächter. Alle 15 Minuten (Cron-Auslöser in wrangler-konto.jsonc) prüft der Dienst, ob die Kosten der Testwochen im Verhältnis
 *      zu den Einnahmen zu hoch werden oder ob zu viele neue Testwochen entstehen, und schickt dann höchstens eine Mail pro Stunde (nur Zahlen, keine Namen).
 *      Eine weitere Tabelle „waechter_stand“ (schema.sql, 13e-3.sql). Nötig dafür: Variable WAECHTER_EMAIL (Empfänger). Alle Schwellen und Preise sind
 *      Variablen mit Standardwerten (siehe „Kosten-Wächter“ weiter unten).
 * 13f-1 (seit 2.0.74, Bau B Verleih): Gäste gibt es ab der Stufe Mittel (und in der Testwoche, die auf Mittel-Niveau läuft); Anzahl Gäste = Geräte der Stufe minus eigene Geräte (Mittel 4, Voll 10, kein eigener Deckel);
 *      der Halter bestätigt bei jeder Einladung, dass er den Nachweis der Person gesehen hat (Art und „gültig bis“, kein Scan). Drei neue Spalten in „freigabe“ (13f-1.sql).
 * 13f-2 (seit 2.0.75, Bau 1 Mitnutzung): Eine Freigabe hat Rechte („lesen“ oder „mitnutzen“). Mit „mitnutzen“ erfasst der Gast Kilometer, Fahrzeugkosten (nicht Fixkosten) und Störungen
 *      im Fahrzeug des Besitzers (mit Namen des Gastes) und erzeugt Kontroll-Codes. Dokumente lassen sich je Freigabe ausnehmen. Drei neue Spalten in „freigabe“ (13f-2.sql).
 * 13f-3 (seit 2.0.76, Bau 2 Störung): Meldet ein Gast mit „mitnutzen“ eine Störung, bekommt der Besitzer eine Info-Mail (nur zur Information, ohne Antwortfunktion, höchstens 5 je Freigabe und Stunde).
 *      Der Gast sieht dazu die früheren Störungen und Arbeiten des Fahrzeugs (nur Texte, keine Beträge), damit die App ähnliche frühere Fälle zeigen kann. Keine neue SQL-Zeile.
 * 13f-4 (seit 2.0.79, Bau 3 Planung): Zwei Zeiträume je Freigabe. Ab „plan_ab“ sieht der Gast das Fahrzeug, plant und macht Reisechecks (sie zählen zum Kontingent des Besitzers),
 *      trägt aber nichts im Fahrzeug ein. Erst ab „ab_am“ gelten seine Rechte (13f-2). Eine neue Spalte in „freigabe“ (13f-4.sql).
 * 13f-8 (seit 2.0.83, Bau 2 Gutscheincodes): Codes beim Bezahlen (PayPal und Überweisung). Rabatt 1 bis 25 % nur für Neukunden beim ersten Kauf (Code für viele mit Obergrenze oder persönlich),
 *      oder genau 100 % als persönlicher Code (Grenze 1): schaltet Mittel oder Voll für 1 bis 12 Monate ohne Zahlung frei, PayPal wird dann nicht aufgerufen. Jeder Code hat ein Ablaufdatum.
 *      Nur Admins legen Codes an (POST /gutschein/anlegen, GET /gutschein/liste, POST /gutschein/loeschen). Kunden: POST /gutschein/pruefen, POST /gutschein/einloesen.
 *      Zwei neue Tabellen und vier neue Spalten (13f-8.sql). Der Beleg weist den Rabatt als eigene Zeile aus.
 * 13f-9 (seit 2.0.84): Beim Anlegen eines Codes kann der Admin eine E-Mail-Adresse des Empfängers eintragen (Feld „empfaenger“, freiwillig). Persönlicher Code (Grenze 1): Mail an die Person,
 *      die ihn einlösen soll. Code für viele (Grenze über 1): Mail an den, der ihn verteilt. Die Adresse wird nicht gespeichert. Die Antwort meldet „mail“ (true oder false);
 *      der Code ist auch ohne Mail angelegt. Keine neue SQL-Zeile.
 * 13f-10 (seit 2.0.88, Routenplanung): POST /route/planen. Der Dienst prüft Anmeldung und Stufe, zählt die Route (eigene Zahl, getrennt von den Online-Checks: Testwoche 10, Mittel 100, Voll 1000 im Jahr,
 *      Nachkauf 100 Routen für 9,99 €), ruft HERE Routing v8 (Truck) mit den Maßen und Gewichten des Fahrzeugs auf und gibt Punkte, Länge, Dauer und Warnungen zurück. Der HERE-Schlüssel
 *      (Secret HERE_SCHLUESSEL) bleibt im Dienst. Schlägt HERE fehl oder findet keine Route, wird nicht gezählt. Zwei neue Tabellen (13f-10.sql: route_nutzung, route_extra).
 * 13f-11 (seit 2.0.94, Verwaltung): GET /verwaltung/statistik (Konten insgesamt, davon Test, Mittel, Voll; Admin und Entwickler) und Zahlungseingänge buchen und freischalten in der App
 *      (/verwaltung/bestellungen, /bestaetigen, /direkt, /loeschen; nur Admins, mit der Anmeldung der App). Die Seite /freischalten mit Passwort bleibt. Keine neue SQL-Zeile.
 * 13e-5 (seit 2.0.73): Rollen-Tabelle „rolle“ (E-Mail, Name, Funktion Admin oder Entwickler). Die App erkennt daran den Bereich „Nur für Entwickler“;
 *      die Tabelle ändern nur Admins (GET /rolle/liste, POST /rolle/setzen, POST /rolle/entfernen). Eine SQL-Zeile (13e-5.sql), dazu der erste Admin von Hand.
 * 13e-4 (seit 2.0.72): Bezahlung. Zwei Wege: PayPal (der Dienst legt die Bestellung bei PayPal an, nach dem Bezahlen schließt er sie ab und schaltet sofort frei)
 *      und Überweisung (Bestellung mit Verwendungszweck, der Betreiber schaltet nach Geldeingang auf der Seite /freischalten frei). Nur Jahreszahlung
 *      (Mittel, Voll), kein Abo, dazu Blöcke zu 5 zusätzlichen Online-Recherchen. Je Zahlung ein Beleg per Mail. Erinnerung 30 und 7 Tage vor dem Ablauf.
 *      Sechs weitere Tabellen (schema.sql, 13e-4.sql). Variablen und Geheimnisse siehe server/EINRICHTUNG.md (PAYPAL_*, UEBERWEISUNG_*, FREISCHALT_TOKEN, BELEG_*).
 */

export const DIENST = 'mobimory-konto';
export const VERSION = '13h';

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

/* ---------- Versionsverträglichkeit App und Dienst (seit 2.0.101) ----------
 * Eine App kann nach langer Pause auf einen neuen Dienst treffen (Beispiel: von 2.0.67 nach 2.1.25 in 11 Monaten). Die Regel:
 *  - Die App hängt ihre Versionsnummer an jede Anfrage an (Parameter „app“, zum Beispiel ?app=2.0.101). Ein Parameter braucht keine neue
 *    CORS-Kopfzeile, deshalb stört er auch einen Dienst nicht, der ihn noch nicht kennt.
 *  - Der Dienst versteht jede App-Version ab der Mindestversion (Variable APP_MINDESTVERSION im Worker, sonst der Standard unten).
 *    Er hebt sie nur an, wenn eine Änderung im Dienst alte Apps nicht mehr versteht, und nie ohne dass vorher die neue App ausgeliefert ist.
 *  - Eine ältere App bekommt Antwort 426 mit „Bitte zuerst aktualisieren“ und die Mindestversion. Ohne Parameter gilt die App als 2.0.100
 *    (die letzte Version vor dieser Regel), damit ältere Apps weiterlaufen, solange die Mindestversion nicht höher liegt.
 *  - Geprüft werden nur Anfragen aus der App (mit Origin). /gesundheit, die Freischalt-Seite und die Verwaltung bleiben frei.
 */
export const APP_MINDESTVERSION_STANDARD = '2.0.100';
export const APP_OHNE_ANGABE = '2.0.100';

export function appVersionTeile(t) {
  const m = /^(\d{1,4})\.(\d{1,4})\.(\d{1,4})$/.exec(String(t === undefined || t === null ? '' : t).trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}
/* -1 kleiner, 0 gleich, 1 größer. Ungültige Angaben gelten als „keine Angabe“. */
export function appVersionVergleich(a, b) {
  const x = appVersionTeile(a) || appVersionTeile(APP_OHNE_ANGABE), y = appVersionTeile(b) || appVersionTeile(APP_OHNE_ANGABE);
  for (let i = 0; i < 3; i++) { if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1; }
  return 0;
}
export function appMindestversion(env) {
  const v = env && typeof env.APP_MINDESTVERSION === 'string' ? env.APP_MINDESTVERSION.trim() : '';
  return appVersionTeile(v) ? v : APP_MINDESTVERSION_STANDARD;
}
function appPruefen(url, env) {
  const min = appMindestversion(env);
  const gesendet = url.searchParams.get('app');
  if (appVersionVergleich(appVersionTeile(gesendet) ? gesendet : APP_OHNE_ANGABE, min) < 0) {
    throw new HttpFehler(426, 'Bitte zuerst aktualisieren. Diese Version von MobiMory ist für den Dienst zu alt.', { appZuAlt: true, mindestversion: min });
  }
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
  await lesenAufraeumen(db, jetzt);
  await bestellungenAufraeumen(db, jetzt);
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

/* Geräte-Lage eines Kontos (seit 2.0.117): Ist die Grenze der Stufe erreicht, und welches ist das älteste angemeldete Gerät? */
async function geraeteLage(db, nutzerId, jetzt, geraet) {
  const st = await stufeVon(db, nutzerId, jetzt, true);
  if (!st || !st.grenzen || st.grenzen.geraete === null) return { voll: false, st: st };
  /* Meldet sich ein Gerät noch einmal an, das schon angemeldet ist (gleiche Kennung), ersetzt es seine alte Sitzung und braucht keinen neuen Platz. */
  const km = /#([a-f0-9]{8,16})$/.exec(geraet || '');
  const z = km
    ? await db.prepare('SELECT COUNT(*) AS n FROM sitzung WHERE nutzer_id = ? AND laeuft_ab > ? AND (geraet IS NULL OR geraet NOT LIKE ?)').bind(nutzerId, jetzt, '%#' + km[1]).first()
    : await db.prepare('SELECT COUNT(*) AS n FROM sitzung WHERE nutzer_id = ? AND laeuft_ab > ?').bind(nutzerId, jetzt).first();
  const voll = !!z && z.n >= st.grenzen.geraete;
  let aeltestes = null;
  if (voll) {
    const a = await db.prepare('SELECT geraet, erstellt_am FROM sitzung WHERE nutzer_id = ? AND laeuft_ab > ? ORDER BY erstellt_am ASC LIMIT 1').bind(nutzerId, jetzt).first();
    if (a) aeltestes = { name: a.geraet || 'Unbekanntes Gerät', erstelltAm: a.erstellt_am };
  }
  return { voll, st, anzahl: z ? z.n : 0, aeltestes };
}

function geraeteVollFehler(lage) {
  const st = lage.st;
  return new HttpFehler(403, 'Mit der Stufe ' + st.name + ' sind höchstens ' + st.grenzen.geraete + ' Geräte erlaubt. Melde zuerst ein anderes Gerät ab.',
    { stufe: st.id, geraeteGrenze: st.grenzen.geraete, geraeteVoll: true, aeltestes: lage.aeltestes });
}

async function sitzungAnlegen(db, nutzerId, geraet, jetzt, aeltestesAbmelden) {
  /* 13e: Die App hängt eine Kennung des Geräts an den Namen („… #ab12cd34“). Meldet sich dasselbe Gerät noch einmal an, ersetzt die neue Sitzung die alte.
     Der Name allein genügt nicht, er ist bei allen Geräten gleich. Danach gilt die Geräte-Grenze der Stufe. */
  const km = /#([a-f0-9]{8,16})$/.exec(geraet || '');
  if (km) await db.prepare('DELETE FROM sitzung WHERE nutzer_id = ? AND geraet LIKE ?').bind(nutzerId, '%#' + km[1]).run();
  const lage = await geraeteLage(db, nutzerId, jetzt);
  if (lage.voll) {
    /* Seit 2.0.117: Mit dem Wunsch „ältestes Gerät abmelden“ macht der Dienst Platz, sonst meldet er die volle Grenze (mit dem ältesten Gerät, damit die App es anbieten kann). */
    if (aeltestesAbmelden !== true) throw geraeteVollFehler(lage);
    const frei = lage.anzahl - lage.st.grenzen.geraete + 1;
    await db.prepare('DELETE FROM sitzung WHERE token_hash IN (SELECT token_hash FROM sitzung WHERE nutzer_id = ? AND laeuft_ab > ? ORDER BY erstellt_am ASC LIMIT ?)').bind(nutzerId, jetzt, frei).run();
  }
  const token = zuBase64Url(zufall(32));
  const laeuftAb = jetzt + SITZUNG_TAGE * TAG;
  await db.prepare('INSERT INTO sitzung (token_hash, nutzer_id, erstellt_am, laeuft_ab, geraet) VALUES (?, ?, ?, ?, ?)')
    .bind(await sha256Hex(token), nutzerId, jetzt, laeuftAb, geraet || null).run();
  return { token, laeuftAb };
}

function geraetName(roh) { return typeof roh === 'string' ? roh.trim().slice(0, 60) : ''; }

async function sitzungAnwort(db, nutzerId, geraet, jetzt, aeltestesAbmelden) {
  const n = await db.prepare('SELECT n.email AS email, n.passwort_hash AS passwort_hash, d.id AS dr_id, d.name AS dr_name FROM nutzer n LEFT JOIN datenraum d ON d.nutzer_id = n.id WHERE n.id = ?').bind(nutzerId).first();
  const s = await sitzungAnlegen(db, nutzerId, geraet, jetzt, aeltestesAbmelden);
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
  /* Seit 2.0.117: Ist die Geräte-Grenze erreicht und hat die App nicht „ältestes Gerät abmelden“ gewünscht, bleibt der richtige Code gültig. Sonst wäre er verbraucht, bevor die App fragen kann. */
  if (b.aeltestesAbmelden !== true) {
    const vorhanden = await db.prepare('SELECT id FROM nutzer WHERE email = ?').bind(email).first();
    if (vorhanden) { const lage = await geraeteLage(db, vorhanden.id, jetzt, geraetName(b.geraet)); if (lage.voll) throw geraeteVollFehler(lage); }
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
  return sitzungAnwort(db, id, geraetName(b.geraet), jetzt, b.aeltestesAbmelden === true);
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
  return sitzungAnwort(db, n.id, geraetName(b.geraet), jetzt, b.aeltestesAbmelden === true);
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

/* Geräteverwaltung (seit 2.0.117): Liste der gültigen Sitzungen dieses Kontos. Die Kennung ist der Anfang des Abdrucks, nicht der Schlüssel selbst. */
async function geraeteListe(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const r = await db.prepare('SELECT token_hash, geraet, erstellt_am, laeuft_ab FROM sitzung WHERE nutzer_id = ? AND laeuft_ab > ? ORDER BY erstellt_am ASC').bind(a.id, jetzt).all();
  const zeilen = (r && r.results) || [];
  return { ok: true, geraete: zeilen.map((z) => ({ kennung: z.token_hash.slice(0, 16), name: z.geraet || 'Unbekanntes Gerät', erstelltAm: z.erstellt_am, laeuftAb: z.laeuft_ab, eigenes: z.token_hash === a.hash })) };
}

/* Beendet die Sitzung eines anderen Geräts des eigenen Kontos. Das eigene Gerät meldet sich mit „abmelden“ ab. */
async function geraetAbmelden(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  const k = typeof b.kennung === 'string' ? b.kennung : '';
  if (!/^[a-f0-9]{16}$/.test(k)) throw new HttpFehler(400, 'Dieses Gerät ist nicht bekannt.', { feld: 'kennung' });
  if (a.hash.slice(0, 16) === k) throw new HttpFehler(400, 'Dieses Gerät meldest du mit „Abmelden“ ab.', { feld: 'kennung' });
  const z = await db.prepare('SELECT token_hash FROM sitzung WHERE nutzer_id = ? AND substr(token_hash, 1, 16) = ?').bind(a.id, k).first();
  if (!z) throw new HttpFehler(404, 'Dieses Gerät ist nicht mehr angemeldet.', { feld: 'kennung' });
  await db.prepare('DELETE FROM sitzung WHERE token_hash = ? AND nutzer_id = ?').bind(z.token_hash, a.id).run();
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
  'kosten', 'kostenstamm', 'kostenarten', 'zahlungsmittel', 'kassen', 'kassenbuchungen', 'routen', 'besuche', 'reisechecks',
  /* seit 2.0.119 (synchron auf allen Geräten): Anforderungen, Standorte und einige Einstellungs-Dokumente */
  'anforderungen', 'standorte', 'einstellungen'];
/* Von den Einstellungen gehen nur diese Dokumente mit (Wechselpunkte, Tagesrouten, Cockpit-Wechsel, Kartenauswahl, Prüfung des Schlüsselworts). */
export const EINSTELLUNG_ID = /^(wechselpunkte-|tagroute-|wechsel-|wache-|kartenwahl|wortpruefung$)/;
export const ABGLEICH_VERLAUF_TYPEN = ['zaehler', 'frist', 'vorgang', 'aktivitaet', 'besatzung', 'verantwortung', 'tagesabschnitt', 'ereignis', 'aktivitaetsart',
  'ereignisart', 'ort', 'gebiet', 'regel', 'person', 'tier', 'adresse',
  'dokument', 'kosten', 'kostenstamm', 'kostenart', 'zahlungsmittel', 'kassenbuchung', 'besuch', 'route', 'nachweisart', 'nachweis'];
/* Vom Nachweis gehen nur diese Angaben hinaus (Nummer, Aussteller, Klassen und Notiz bleiben auf dem Gerät). */
export const NACHWEIS_FELDER = ['ausgestelltAm', 'gueltigBis', 'dateiName', 'dateiTyp', 'dateiGroesse'];
/* Das Feld „namen“ des Reisechecks (Namen hinter den Decknamen) bleibt auf dem Gerät. */
export const EXTRA_LOKAL = { reisechecks: ['namen'] };
/* „gpsdaten“ (seit 2.0.119): die GPS-Spur einer Aktivität als eine verschlüsselte Datei. */
export const DATEI_TABELLEN = ['dateien', 'nachweisdateien', 'ereignisdateien', 'gpsdaten'];
/* Diese Angaben gehen nie im Klartext hinaus. Taucht einer dieser Schlüssel in einem Datensatz auf, lehnt der Dienst ihn ab.
   Seit 2.0.119 kommen die empfindlichen Angaben als Block „@geheim“, verschlüsselt mit dem Schlüsselwort des Nutzers; der Dienst kann ihn nicht lesen. */
export const LOKALE_SCHLUESSEL = ['notiz', 'abschlussNotiz', 'erledigtNotiz', 'email', 'telefon', 'chipnummer', 'adresse', 'ansprechpartner',
  'geburtsdatum', 'wohnort', 'inhalt', 'spur', 'geheim', 'wachepos'];

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
  if (d.tabelle === 'einstellungen' && !EINSTELLUNG_ID.test(d.id)) throw new HttpFehler(400, 'Diese Einstellung nimmt der Dienst nicht an.', { feld: 'id' });
  if (Object.prototype.hasOwnProperty.call(o, '@geheim') && (typeof o['@geheim'] !== 'string' || !/^v1\.[A-Za-z0-9+/]+={0,2}$/.test(o['@geheim']))) throw new HttpFehler(400, 'Der verschlüsselte Teil eines Datensatzes ist ungültig.', { feld: 'nutzlast' });
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
  /* Seit 2.0.119: Testwoche, Mittel und Voll gleichen von allein ab, Basic nur von Hand. Die App fragt das bei jeder kleinen Abfrage mit. */
  const st = await stufeVon(db, a.id, jetzt, true);
  return { ok: true, seq: z.seq, epoche: z.epoche, anzahl: n ? n.n : 0, automatisch: !!(st && st.grenzen && st.grenzen.online), stufe: st ? st.id : null };
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
  return { ok: true, groesse: laenge, verschluesselt: !!verschluesselt, am: jetzt };
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
  const r = await db.prepare("SELECT tabelle, objekt_id, groesse, verschluesselt, erstellt_am FROM datei WHERE datenraum_id = ? AND (tabelle || '/' || objekt_id) > ? ORDER BY (tabelle || '/' || objekt_id) LIMIT ?").bind(dr, nach, DATEI_SEITE + 1).all();
  const alle = r.results || [], weiter = alle.length > DATEI_SEITE, seite = alle.slice(0, DATEI_SEITE);
  const sum = await db.prepare('SELECT COALESCE(SUM(groesse), 0) AS n FROM datei WHERE datenraum_id = ?').bind(dr).first();
  return { ok: true, weiter, nach: seite.length ? seite[seite.length - 1].tabelle + '/' + seite[seite.length - 1].objekt_id : nach, belegt: sum ? sum.n : 0, grenze: MAX_KONTO_DATEI_BYTES,
    dateien: seite.map((x) => ({ tabelle: x.tabelle, id: x.objekt_id, groesse: x.groesse, verschluesselt: !!x.verschluesselt, am: x.erstellt_am === undefined ? null : x.erstellt_am })) };
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
  if (f.ab_am > jetzt) return f.plan_ab !== null && f.plan_ab !== undefined && f.plan_ab <= jetzt ? 'planung' : 'wartet';
  return 'aktiv';
}

const NAME_VON_FAHRZEUG = "(SELECT json_extract(e.nutzlast, '$.werte.bezeichnung') FROM abgleich e WHERE e.datenraum_id = f.datenraum_id AND e.tabelle = 'eintraege' AND e.fahrzeug_id = f.fahrzeug_id AND e.geloescht = 0 ORDER BY json_extract(e.nutzlast, '$.nr') DESC LIMIT 1)";

/* Gäste (Bau B, 2.0.74): Gäste gibt es nur mit Online-Stufe (Testwoche, Mittel, Voll, Entwickler), Basic hat keine. Die Zahl der Gäste ist die Zahl der Geräte der Stufe
   minus die eigenen Geräte (angemeldete Geräte des Besitzers). Es gibt keinen eigenen Deckel. Ein Gast zählt einmal, auch bei mehreren Fahrzeugen. */
async function gaesteStand(db, a, dr, jetzt, ohneEmail) {
  const st = await stufeVon(db, a.id, jetzt, true);
  if (!st) return { st: null, erlaubt: true, grenze: null, eigene: 0, belegt: 0, frei: null };
  const eigene = await db.prepare('SELECT COUNT(*) AS n FROM sitzung WHERE nutzer_id = ? AND laeuft_ab > ?').bind(a.id, jetzt).first();
  const belegt = await db.prepare('SELECT COUNT(DISTINCT email) AS n FROM freigabe WHERE datenraum_id = ? AND widerrufen_am IS NULL AND laeuft_ab > ? AND (angenommen_am IS NOT NULL OR einladung_bis > ?) AND email <> ?')
    .bind(dr, jetzt, jetzt, ohneEmail || '').first();
  const e = eigene ? eigene.n : 0, b = belegt ? belegt.n : 0;
  const grenze = st.grenzen.geraete === null || st.grenzen.geraete === undefined ? null : Math.max(0, st.grenzen.geraete - e);
  return { st, erlaubt: !!st.grenzen.online, grenze, eigene: e, belegt: b, frei: grenze === null ? null : Math.max(0, grenze - b) };
}

/* Der Halter bestätigt, dass er den Nachweis gesehen hat (Art und „gültig bis“). Es wird kein Scan und keine Nummer gespeichert. */
function befaehigungPruefen(b, bis) {
  const art = typeof b.nachweisArt === 'string' ? b.nachweisArt.trim() : '';
  if (!art) throw new HttpFehler(400, 'Bitte angeben, welchen Nachweis du gesehen hast (zum Beispiel Führerschein).', { feld: 'nachweisArt' });
  if (art.length > 60) throw new HttpFehler(400, 'Die Bezeichnung des Nachweises ist zu lang (höchstens 60 Zeichen).', { feld: 'nachweisArt' });
  let nachweisBis = null;
  if (b.nachweisBis !== undefined && b.nachweisBis !== null && b.nachweisBis !== '') {
    if (!datumTeile(b.nachweisBis)) throw new HttpFehler(400, 'Das Datum „Nachweis gültig bis“ ist ungültig.', { feld: 'nachweisBis' });
    if (b.nachweisBis < bis) throw new HttpFehler(400, 'Der Nachweis läuft am ' + b.nachweisBis + ' ab, die Freigabe endet am ' + bis + '. Kürze die Freigabe oder lass den Nachweis erneuern.', { feld: 'nachweisBis' });
    nachweisBis = b.nachweisBis;
  }
  if (b.bestaetigt !== true) throw new HttpFehler(400, 'Bitte bestätige, dass du den Nachweis der Person gesehen hast. Ohne diese Bestätigung gibt es keinen Verleih.', { feld: 'bestaetigt' });
  return { art, bis: nachweisBis };
}

/* Rechte der Freigabe (13f-2). „lesen“ = nur ansehen (wie bisher), „mitnutzen“ = der Gast erfasst Kilometer, Fahrzeugkosten und Störungen und erzeugt Kontroll-Codes.
   Mit „mitnutzen“ braucht der Gast einen Namen, der an seinen Einträgen steht. Dokumente lassen sich je Freigabe ausnehmen (zum Beispiel der Kaufvertrag). */
const RECHTE = ['lesen', 'mitnutzen'];
const MAX_AUSNAHMEN = 50;
function mitnutzungPruefen(b) {
  const rechte = b.rechte === undefined || b.rechte === null || b.rechte === '' ? 'lesen' : b.rechte;
  if (!RECHTE.includes(rechte)) throw new HttpFehler(400, 'Diese Rechte gibt es nicht. Erlaubt sind „lesen“ und „mitnutzen“.', { feld: 'rechte' });
  const gastName = typeof b.gastName === 'string' ? b.gastName.trim() : '';
  if (gastName.length > 40) throw new HttpFehler(400, 'Der Name ist zu lang (höchstens 40 Zeichen).', { feld: 'gastName' });
  if (rechte === 'mitnutzen' && !gastName) throw new HttpFehler(400, 'Bitte einen Namen angeben. Er steht an den Einträgen der Person (zum Beispiel „Anna“).', { feld: 'gastName' });
  let ausnahmen = [];
  if (b.ausnahmen !== undefined && b.ausnahmen !== null) {
    if (!Array.isArray(b.ausnahmen) || b.ausnahmen.length > MAX_AUSNAHMEN) throw new HttpFehler(400, 'Die Liste der ausgenommenen Dokumente ist ungültig (höchstens ' + MAX_AUSNAHMEN + ').', { feld: 'ausnahmen' });
    ausnahmen = [...new Set(b.ausnahmen.map((x) => kennung(x, 'ausnahmen')))];
  }
  return { rechte, gastName: gastName || null, ausnahmen };
}
function ausnahmenLesen(roh) {
  if (!roh) return [];
  try { const l = JSON.parse(roh); return Array.isArray(l) ? l.filter((x) => typeof x === 'string') : []; } catch (e) { return []; }
}

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
  /* Zwei Zeiträume (13f-4): „planAb“ ist der Beginn der Planung. Ab dann sieht der Gast das Fahrzeug, plant und macht Reisechecks. Eintragen darf er erst ab „ab“. */
  let planAb = null;
  if (b.planAb !== undefined && b.planAb !== null && b.planAb !== '') {
    if (!datumTeile(b.planAb)) throw new HttpFehler(400, 'Das Datum „Planung ab“ ist ungültig.', { feld: 'planAb' });
    if (b.planAb < heute) throw new HttpFehler(400, 'Das Datum „Planung ab“ liegt in der Vergangenheit.', { feld: 'planAb' });
    if (b.planAb > ab) throw new HttpFehler(400, 'Die Planung muss vor oder am Tag des Verleihs beginnen.', { feld: 'planAb' });
    if (ab > plusMonate(b.planAb, FREIGABE_MONATE)) throw new HttpFehler(400, 'Die Planung darf höchstens ' + FREIGABE_MONATE + ' Monate vor dem Verleih beginnen.', { feld: 'planAb' });
    if (b.planAb < ab) planAb = b.planAb;
  }
  if (!(await fahrzeugDa(db, dr, fz))) throw new HttpFehler(404, 'Dieses Fahrzeug liegt nicht beim Dienst. Bitte zuerst unter Funktionen › Konto abgleichen.', { feld: 'fahrzeugId' });
  const gs = await gaesteStand(db, a, dr, jetzt, email);
  if (!gs.erlaubt) throw new HttpFehler(403, 'Gäste einladen geht ab der Stufe Mittel. Mit Basic ist das nicht möglich.', { stufe: gs.st.id });
  if (gs.grenze !== null && gs.belegt >= gs.grenze) {
    throw new HttpFehler(409, gs.grenze === 0
      ? 'Alle ' + gs.st.grenzen.geraete + ' Geräte der Stufe ' + gs.st.name + ' nutzt du selbst, für Gäste bleibt kein Platz. Melde ein eigenes Gerät ab oder wechsle in eine größere Stufe.'
      : 'Mit der Stufe ' + gs.st.name + ' hast du ' + gs.st.grenzen.geraete + ' Geräte, ' + gs.eigene + ' nutzt du selbst. Die ' + gs.grenze + ' Plätze für Gäste sind vergeben. Storniere eine Freigabe oder melde ein eigenes Gerät ab.',
      { stufe: gs.st.id });
  }
  const bf = befaehigungPruefen(b, b.bis);
  const mn = mitnutzungPruefen(b);
  await bremsen(db, await schluesselFuer('fre-e', a.id), 20, 60 * MINUTE, jetzt, 'Du hast in kurzer Zeit zu viele Einladungen verschickt.');
  const offen = await db.prepare('SELECT COUNT(*) AS n FROM freigabe WHERE datenraum_id = ? AND widerrufen_am IS NULL AND laeuft_ab > ?').bind(dr, jetzt).first();
  if (offen && offen.n >= MAX_FREIGABEN) throw new HttpFehler(409, 'Es gibt schon ' + MAX_FREIGABEN + ' gültige Freigaben. Bitte widerrufe zuerst eine.');
  const code = zufallCode(EINLADUNG_CODE_LAENGE);
  const id = crypto.randomUUID();
  const laeuftAb = tagEnde(b.bis), abAm = tagAnfang(ab), einladungBis = Math.min(laeuftAb, jetzt + EINLADUNG_TAGE * TAG);
  /* Gleiches Fahrzeug und gleicher Gast: Die ältere Freigabe wird ersetzt. */
  const spalten = 'id, datenraum_id, fahrzeug_id, email, code_hash, erstellt_am, ab_am, laeuft_ab, einladung_bis, nachweis_art, nachweis_bis, bestaetigt_am, rechte, gast_name, ausnahmen' + (planAb ? ', plan_ab' : '');
  const werte = [id, dr, fz, email, await codeAbdruck(env, 'freigabe', code), jetzt, abAm, laeuftAb, einladungBis, bf.art, bf.bis, jetzt, mn.rechte, mn.gastName, mn.ausnahmen.length ? JSON.stringify(mn.ausnahmen) : null];
  if (planAb) werte.push(tagAnfang(planAb));
  try {
    await db.batch([
      db.prepare('UPDATE freigabe SET widerrufen_am = ? WHERE datenraum_id = ? AND fahrzeug_id = ? AND email = ? AND widerrufen_am IS NULL').bind(jetzt, dr, fz, email),
      db.prepare('INSERT INTO freigabe (' + spalten + ') VALUES (' + werte.map(() => '?').join(', ') + ')').bind(...werte)
    ]);
  } catch (e) {
    if (/no such column|has no column/i.test(String(e && e.message || e))) throw new HttpFehler(503, planAb ? 'Im Dienst fehlt die SQL-Zeile 13f-4 (Planung vor dem Verleih). Siehe server/EINRICHTUNG.md, „Update auf 13f-4“.' : 'Im Dienst fehlt eine SQL-Zeile (13f-1 Verleih oder 13f-2 Mitnutzung). Siehe server/EINRICHTUNG.md, „Update auf 13f-2“.');
    throw e;
  }
  let r;
  try {
    r = await mailSenden(env, email, 'Ein Fahrzeug wurde für dich in MobiMory freigegeben',
      a.email + ' verleiht dir ein Fahrzeug (' + (mn.rechte === 'mitnutzen' ? 'du kannst Kilometer, Kosten und Störungen eintragen' : 'du kannst die Angaben dazu nur lesen') + '), gültig von ' + ab + ' bis ' + b.bis + '.' + (planAb ? ' Ab dem ' + planAb + ' kannst du das Fahrzeug schon ansehen, deine Reise planen und Reisechecks machen. Eintragen im Fahrzeug kannst du erst ab dem ' + ab + '.' : '') + '\n\nDein Code: ' + code + '\n\nMelde dich in MobiMory mit dieser E-Mail-Adresse an und trage den Code unter Funktionen › Verleih ein. Er gilt ' + EINLADUNG_TAGE + ' Tage und nur einmal.\n\nWenn du die Einladung nicht erwartest, ignoriere diese E-Mail. Es passiert nichts.');
  } catch (e) {
    await db.prepare('DELETE FROM freigabe WHERE id = ?').bind(id).run();
    throw e;
  }
  return { ok: true, id, ab, planAb, bis: b.bis, einladungBis, codeGesendet: !!r.gesendet, entwicklungsCode: r.entwicklung ? code : undefined };
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
  const kopf = 'SELECT f.id, f.fahrzeug_id, f.email, f.ab_am, f.laeuft_ab, f.einladung_bis, f.angenommen_am, f.widerrufen_am, ';
  const fuss = NAME_VON_FAHRZEUG + ' AS name FROM freigabe f WHERE f.datenraum_id = ? ORDER BY f.erstellt_am DESC LIMIT 200';
  let g, verleihSpalten = true, mitnutzungSpalten = true, planungSpalte = true;
  try { g = await db.prepare(kopf + 'f.nachweis_art, f.nachweis_bis, f.bestaetigt_am, f.rechte, f.gast_name, f.ausnahmen, f.plan_ab, ' + fuss).bind(dr).all(); } catch (e0) {
    if (!/no such column/i.test(String(e0 && e0.message || e0))) throw e0;
    planungSpalte = false;
  }
  if (!g) try { g = await db.prepare(kopf + 'f.nachweis_art, f.nachweis_bis, f.bestaetigt_am, f.rechte, f.gast_name, f.ausnahmen, ' + fuss).bind(dr).all(); } catch (e) {
    if (!/no such column/i.test(String(e && e.message || e))) throw e;
    mitnutzungSpalten = false;
    try { g = await db.prepare(kopf + 'f.nachweis_art, f.nachweis_bis, f.bestaetigt_am, ' + fuss).bind(dr).all(); } catch (e2) {
      if (!/no such column/i.test(String(e2 && e2.message || e2))) throw e2;
      verleihSpalten = false;
      g = await db.prepare(kopf + fuss).bind(dr).all();
    }
  }
  const gs = await gaesteStand(db, a, dr, jetzt, '');
  const erhaltenSql = (rechteSpalte) => 'SELECT f.id, f.fahrzeug_id, n.email AS von, f.ab_am, f.laeuft_ab, f.einladung_bis, f.angenommen_am, f.widerrufen_am, ' + rechteSpalte + NAME_VON_FAHRZEUG + ' AS name FROM freigabe f JOIN datenraum d ON d.id = f.datenraum_id JOIN nutzer n ON n.id = d.nutzer_id WHERE f.gast_nutzer_id = ? ORDER BY f.erstellt_am DESC LIMIT 200';
  let e;
  try { e = await db.prepare(erhaltenSql('f.rechte, f.plan_ab, ')).bind(a.id).all(); } catch (x) {
    if (!/no such column/i.test(String(x && x.message || x))) throw x;
    try { e = await db.prepare(erhaltenSql('f.rechte, ')).bind(a.id).all(); } catch (x2) {
      if (!/no such column/i.test(String(x2 && x2.message || x2))) throw x2;
      e = await db.prepare(erhaltenSql('')).bind(a.id).all();
    }
  }
  const k = await db.prepare('SELECT f.id, f.fahrzeug_id, f.laeuft_ab, f.widerrufen_am, ' + NAME_VON_FAHRZEUG + ' AS name FROM kontrolle f WHERE f.datenraum_id = ? ORDER BY f.erstellt_am DESC LIMIT 200').bind(dr).all();
  const tag = (ms) => datumText(ms);
  return {
    ok: true,
    verleih: {
      spalten: verleihSpalten, mitnutzung: mitnutzungSpalten, planung: planungSpalte, erlaubt: gs.erlaubt, stufe: gs.st ? gs.st.id : null, stufeName: gs.st ? gs.st.name : null,
      gaeste: { grenze: gs.grenze, eigene: gs.eigene, belegt: gs.belegt, frei: gs.frei }
    },
    gegeben: (g.results || []).map((f) => ({ id: f.id, fahrzeugId: f.fahrzeug_id, name: f.name || null, email: f.email, ab: tag(f.ab_am), bis: tag(f.laeuft_ab), status: freigabeStatus(f, jetzt),
      planAb: f.plan_ab ? tag(f.plan_ab) : null, nachweisArt: f.nachweis_art || null, nachweisBis: f.nachweis_bis || null, bestaetigtAm: f.bestaetigt_am ? datumText(f.bestaetigt_am) : null,
      rechte: f.rechte || 'lesen', gastName: f.gast_name || null, ausnahmen: ausnahmenLesen(f.ausnahmen).length })),
    erhalten: (e.results || []).filter((f) => !f.widerrufen_am).map((f) => ({ id: f.id, fahrzeugId: f.fahrzeug_id, name: f.name || null, von: f.von, ab: tag(f.ab_am), planAb: f.plan_ab ? tag(f.plan_ab) : null, bis: tag(f.laeuft_ab), status: freigabeStatus(f, jetzt), rechte: f.rechte || 'lesen' })),
    kontrollen: (k.results || []).map((f) => ({ id: f.id, fahrzeugId: f.fahrzeug_id, name: f.name || null, laeuftAb: f.laeuft_ab, status: f.widerrufen_am ? 'widerrufen' : (f.laeuft_ab <= jetzt ? 'abgelaufen' : 'aktiv') }))
  };
}

/* Die Freigabe, die dieses Konto gerade zum Lesen berechtigt. Alles andere ist 403, nie mehr Auskunft als nötig. */
async function gastFreigabe(db, a, id, jetzt, schreiben) {
  const sql = (extra) => 'SELECT id, datenraum_id, fahrzeug_id, gast_nutzer_id, ab_am, laeuft_ab, angenommen_am, widerrufen_am' + extra + ' FROM freigabe WHERE id = ?';
  let f = null;
  /* Neueste Spalten zuerst (13f-4: plan_ab), dann 13f-2 (Rechte), dann ohne. */
  for (const extra of [', rechte, gast_name, ausnahmen, plan_ab', ', rechte, gast_name, ausnahmen', '']) {
    try { f = await db.prepare(sql(extra)).bind(kennung(id, 'freigabe')).first(); break; } catch (e) {
      if (!/no such column/i.test(String(e && e.message || e))) throw e;
    }
  }
  if (!f || f.gast_nutzer_id !== a.id || !f.angenommen_am || f.widerrufen_am || f.laeuft_ab <= jetzt) throw new HttpFehler(403, 'Diese Freigabe gilt nicht (mehr).');
  /* Zwei Zeiträume (13f-4): Ab „plan_ab“ sieht der Gast das Fahrzeug und darf planen und prüfen (Phase „planung“), ab „ab_am“ gelten seine Rechte (Phase „nutzung“). */
  const planAb = f.plan_ab === null || f.plan_ab === undefined ? null : f.plan_ab;
  if (f.ab_am <= jetzt) f.phase = 'nutzung';
  else if (planAb !== null && planAb <= jetzt) f.phase = 'planung';
  else throw new HttpFehler(403, 'Diese Freigabe gilt nicht (mehr).');
  if (schreiben && f.phase !== 'nutzung') throw new HttpFehler(403, 'Eintragen im Fahrzeug geht erst ab ' + datumText(f.ab_am) + '. Bis dahin kannst du planen und Reisechecks machen.', { phase: 'planung', ab: datumText(f.ab_am) });
  f.planAb = planAb;
  f.rechte = f.rechte === 'mitnutzen' ? 'mitnutzen' : 'lesen';
  f.ausnahmenListe = ausnahmenLesen(f.ausnahmen);
  return f;
}

const SICHT_VORGAENGE = 200;
const J = (feld) => "json_extract(x.nutzlast, '" + feld + "')";

/* Die Datensätze, die ein Gast zu einem Fahrzeug sieht. Der Dienst liefert sie in der Form des Abgleichs, die App baut daraus die Ansicht.
   gast: Fahrzeug, aktuelle Angaben, Fristen samt Erledigungen, Zähler, Dokumente samt Dateien, letztes Prüfergebnis.
   kontrolle: nur Fahrzeug, Dokumente samt Dateien und das letzte Prüfergebnis.
   Nie dabei: Kosten, Notizen, Nachweise, Reisechecks, Routen, Besuche, Ereignisse und Aktivitäten, Personen, Orte, GPS. */
async function fahrzeugSicht(db, dr, fz, umfang, ausnahmen, mitVorgaenge) {
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
    /* 13f-3: Mit dem Recht „mitnutzen“ sieht der Gast auch die früheren Störungen und Arbeiten (nur Texte), damit MobiMory ähnliche frühere Fälle zeigen kann. Nie Beträge, nie Dokumente daran. */
    if (mitVorgaenge) {
      await holen(AUS + "x.tabelle = 'vorgaenge' AND x.fahrzeug_id = ? ORDER BY x.seq DESC LIMIT " + SICHT_VORGAENGE, dr, fz);
      await holen(verlaufVon('vorgang', 'vorgaenge'), dr, dr, fz);
    }
  }
  /* Ausgenommene Dokumente (13f-2): weder das Dokument noch sein Verlauf noch seine Dateien gehen hinaus. */
  if (ausnahmen && ausnahmen.length) {
    const weg = new Set(ausnahmen);
    return k.filter((x) => {
      if (x.tabelle === 'dokumente') return !weg.has(x.id);
      let o = null;
      if (x.tabelle === 'verlaeufe' || x.tabelle === 'dateien') { try { o = JSON.parse(x.nutzlast); } catch (e) { return true; } }
      if (x.tabelle === 'verlaeufe' && o && o.objektTyp === 'dokument') return !weg.has(o.objektId);
      if (x.tabelle === 'dateien' && o) return !weg.has(o.dokumentId);
      return true;
    });
  }
  return k;
}

async function geteiltFahrzeug(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const f = await gastFreigabe(db, a, new URL(request.url).searchParams.get('freigabe'), jetzt);
  const s = await fahrzeugSicht(db, f.datenraum_id, f.fahrzeug_id, 'gast', f.ausnahmenListe, f.rechte === 'mitnutzen');
  if (!s) throw new HttpFehler(404, 'Dieses Fahrzeug wird nicht mehr geteilt.');
  const antw = { ok: true, fahrzeugId: f.fahrzeug_id, bis: datumText(f.laeuft_ab), rechte: f.rechte, phase: f.phase, nutzungAb: datumText(f.ab_am), planAb: f.planAb === null ? null : datumText(f.planAb), datensaetze: s };
  if (f.rechte === 'mitnutzen' && f.phase === 'nutzung') antw.eigene = await gastEintraege(db, f);
  return antw;
}

/* Datei zu einem Dokument des freigegebenen Fahrzeugs. Nachweis-Scans und Fotos sind nie erreichbar. */
async function dokumentDatei(env, db, dr, fz, dateiId, ausnahmen) {
  const r2 = dateiSpeicher(env);
  const id = kennung(dateiId, 'id');
  const d = await db.prepare("SELECT x.nutzlast AS nutzlast FROM abgleich x WHERE x.datenraum_id = ? AND x.tabelle = 'dateien' AND x.objekt_id = ? AND x.geloescht = 0 AND json_extract(x.nutzlast, '$.dokumentId') IN (SELECT objekt_id FROM abgleich WHERE datenraum_id = ? AND tabelle = 'dokumente' AND fahrzeug_id = ? AND geloescht = 0)").bind(dr, id, dr, fz).first();
  if (!d) throw new HttpFehler(404, 'Diese Datei gibt es hier nicht.');
  if (ausnahmen && ausnahmen.length) {
    let dok = null;
    try { dok = JSON.parse(d.nutzlast).dokumentId; } catch (e) { dok = null; }
    if (ausnahmen.includes(dok)) throw new HttpFehler(404, 'Diese Datei gibt es hier nicht.');
  }
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
  return dokumentDatei(env, db, f.datenraum_id, f.fahrzeug_id, u.searchParams.get('id'), f.ausnahmenListe);
}

/* ---------- 13f-2: Mitnutzung durch den Gast (Bau 1) ----------
   Mit dem Recht „mitnutzen“ erfasst ein Gast im Fahrzeug des Besitzers: Kilometer, Fahrzeugkosten (variabel und Instandhaltung, nie Fixkosten) und Störungen.
   Der Dienst baut die Datensätze selbst (der Gast schickt nur seine Eingaben), setzt das Fahrzeug aus der Freigabe und schreibt sie in den Datenraum des Besitzers.
   Sie tragen den Namen des Gastes (Feld „gast“) und erscheinen beim Besitzer nach dem nächsten Abgleich. Der Gast kann keinen Datensatz des Besitzers ändern:
   Es gibt nur neue Einträge. Reisekosten (Campingplatz, Essen, Souvenirs) gehören nicht hierher, sie bleiben beim Gast. */
export const GAST_KOSTENARTEN = {
  variabel: ['treibstoff', 'unterwegs', 'gebuehren', 'kurtaxe', 'muell', 'strom', 'wasser', 'duschmarken', 'varsonst'],
  instandhaltung: ['teile', 'arbeit', 'fremd', 'instsonst']
};
export const GAST_AUSWIRKUNGEN = ['keine', 'bedingt', 'nicht'];
const MAX_GAST_EINTRAEGE = 500;
const MAX_BEZEICHNUNG = 80;
const MAX_BESCHREIBUNG = 500;

function gastZahl(roh, feld, min, max, text) {
  const n = typeof roh === 'string' ? Number(roh.replace(',', '.')) : roh;
  if (typeof n !== 'number' || !Number.isFinite(n) || n < min || n > max) throw new HttpFehler(400, text, { feld });
  return n;
}
function gastText(roh, feld, max, pflicht, text) {
  const t = typeof roh === 'string' ? roh.trim() : '';
  if (!t && pflicht) throw new HttpFehler(400, text, { feld });
  if (t.length > max) throw new HttpFehler(400, 'Der Text ist zu lang (höchstens ' + max + ' Zeichen).', { feld });
  return t || null;
}
function gastDatum(roh, jetzt) {
  const heute = datumText(jetzt);
  const d = roh === undefined || roh === null || roh === '' ? heute : roh;
  if (!datumTeile(d)) throw new HttpFehler(400, 'Das Datum ist ungültig.', { feld: 'datum' });
  if (d > datumText(jetzt + TAG)) throw new HttpFehler(400, 'Das Datum liegt in der Zukunft.', { feld: 'datum' });
  return d;
}
function gastMarke(f) { return { freigabe: f.id, name: f.gast_name || 'Gast' }; }
function jsonZeit(jetzt) { return new Date(jetzt).toISOString(); }

/* Schreibt neue Datensätze in den Datenraum des Besitzers (nur neue Kennungen, nie ein Überschreiben). */
async function abgleichNeu(db, dr, liste, jetzt) {
  await abgleichStand(db, dr);
  const z = await db.prepare('UPDATE abgleich_stand SET seq = seq + ? WHERE datenraum_id = ? RETURNING seq, epoche').bind(liste.length, dr).first();
  const erste = z.seq - liste.length;
  await db.batch(liste.map((x, i) => db.prepare('INSERT INTO abgleich (datenraum_id, tabelle, objekt_id, seq, geloescht, fahrzeug_id, nutzlast, geaendert_am) VALUES (?, ?, ?, ?, 0, ?, ?, ?)')
    .bind(dr, x.tabelle, x.id, erste + i + 1, x.fahrzeugId || null, JSON.stringify(x.objekt), jetzt)));
}

async function gastAnzahl(db, f) {
  const r = await db.prepare("SELECT COUNT(*) AS n FROM abgleich x WHERE x.datenraum_id = ? AND x.geloescht = 0 AND x.tabelle <> 'verlaeufe' AND " + J('$.gast.freigabe') + ' = ?').bind(f.datenraum_id, f.id).first();
  return r ? r.n : 0;
}

/* Die Einträge, die dieser Gast gemacht hat (für seine Seite). Der Stand einer Störung kommt aus ihrem neuesten Verlauf. */
async function gastEintraege(db, f) {
  const r = await db.prepare("SELECT x.tabelle, x.objekt_id, x.nutzlast FROM abgleich x WHERE x.datenraum_id = ? AND x.geloescht = 0 AND x.tabelle IN ('kosten', 'vorgaenge', 'zaehlerstaende') AND " + J('$.gast.freigabe') + ' = ? ORDER BY x.seq DESC LIMIT 100')
    .bind(f.datenraum_id, f.id).all();
  const liste = [];
  for (const x of (r.results || [])) {
    let o; try { o = JSON.parse(x.nutzlast); } catch (e) { continue; }
    if (x.tabelle === 'zaehlerstaende') { liste.push({ art: 'kilometer', id: x.objekt_id, datum: o.datum || null, wert: o.wert, zaehlerId: o.zaehlerId }); continue; }
    const typ = x.tabelle === 'kosten' ? 'kosten' : 'vorgang';
    const v = await db.prepare("SELECT x.nutzlast FROM abgleich x WHERE x.datenraum_id = ? AND x.tabelle = 'verlaeufe' AND x.geloescht = 0 AND " + J('$.objektTyp') + ' = ? AND ' + J('$.objektId') + ' = ? ORDER BY ' + J('$.nr') + ' DESC LIMIT 1')
      .bind(f.datenraum_id, typ, x.objekt_id).first();
    let w = {}; try { w = (JSON.parse(v.nutzlast).werte) || {}; } catch (e) { w = {}; }
    if (x.tabelle === 'kosten') liste.push({ art: 'kosten', id: x.objekt_id, datum: w.datum || null, titel: w.bezeichnung || 'Kosten', betrag: w.betrag, gruppe: w.gruppe, ausgeblendet: w.ausgeblendet === 'ja' });
    else liste.push({ art: 'stoerung', id: x.objekt_id, datum: w.gemeldetAm || null, titel: w.bezeichnung || 'Störung', auswirkung: w.auswirkung || null, status: w.status || 'offen' });
  }
  return liste;
}

async function gastFahrzeugRecord(db, f) {
  const r = await db.prepare("SELECT nutzlast FROM abgleich WHERE datenraum_id = ? AND tabelle = 'fahrzeuge' AND objekt_id = ? AND geloescht = 0").bind(f.datenraum_id, f.fahrzeug_id).first();
  if (!r) throw new HttpFehler(404, 'Dieses Fahrzeug wird nicht mehr geteilt.');
  try { return JSON.parse(r.nutzlast); } catch (e) { throw new HttpFehler(404, 'Dieses Fahrzeug wird nicht mehr geteilt.'); }
}

async function geteiltErfassen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  const f = await gastFreigabe(db, a, b.freigabe, jetzt, true);
  if (f.rechte !== 'mitnutzen') throw new HttpFehler(403, 'Diese Freigabe erlaubt nur das Ansehen. Der Besitzer kann dir die Mitnutzung geben.');
  await bremsen(db, await schluesselFuer('gast-e', a.id), 120, 60 * MINUTE, jetzt, 'Du hast in kurzer Zeit zu viele Einträge gemacht.');
  if ((await gastAnzahl(db, f)) >= MAX_GAST_EINTRAEGE) throw new HttpFehler(409, 'Für diese Freigabe gibt es schon ' + MAX_GAST_EINTRAEGE + ' Einträge. Bitte den Besitzer fragen.');
  const fz = await gastFahrzeugRecord(db, f), fzId = f.fahrzeug_id, dr = f.datenraum_id;
  const marke = gastMarke(f), zeit = jsonZeit(jetzt), neueKennung = (p) => p + '-g-' + crypto.randomUUID();
  const art = b.art;
  const liste = [];
  if (art === 'kilometer') {
    const zid = kennung(b.zaehlerId, 'zaehlerId');
    const z = await db.prepare("SELECT nutzlast FROM abgleich WHERE datenraum_id = ? AND tabelle = 'zaehler' AND objekt_id = ? AND fahrzeug_id = ? AND geloescht = 0").bind(dr, zid, fzId).first();
    let zo = null; try { zo = z ? JSON.parse(z.nutzlast) : null; } catch (e) { zo = null; }
    if (!zo || zo.art !== 'strecke') throw new HttpFehler(404, 'Diesen Kilometerzähler gibt es an diesem Fahrzeug nicht.', { feld: 'zaehlerId' });
    const wert = gastZahl(b.wert, 'wert', 0, 10000000, 'Bitte den Kilometerstand als Zahl eingeben.');
    const datum = gastDatum(b.datum, jetzt);
    const alle = await db.prepare("SELECT nutzlast FROM abgleich x WHERE x.datenraum_id = ? AND x.tabelle = 'zaehlerstaende' AND x.geloescht = 0 AND " + J('$.zaehlerId') + ' = ?').bind(dr, zid).all();
    let nr = 0, hoechster = null;
    for (const r of (alle.results || [])) {
      let o; try { o = JSON.parse(r.nutzlast); } catch (e) { continue; }
      if ((o.nr || 0) > nr) nr = o.nr || 0;
      if (typeof o.wert === 'number' && String(o.datum || '') <= datum && (hoechster === null || o.wert > hoechster)) hoechster = o.wert;
    }
    if (hoechster !== null && wert < hoechster) throw new HttpFehler(400, 'Der Stand ist niedriger als ein früherer Stand (' + hoechster + '). Bitte prüfen.', { feld: 'wert' });
    const id = neueKennung('zs');
    liste.push({ tabelle: 'zaehlerstaende', id, fahrzeugId: null, objekt: { id, zaehlerId: zid, nr: nr + 1, wert, datum, quelle: 'hand', erstelltAm: zeit, gast: marke } });
  } else if (art === 'kosten') {
    const gruppe = b.gruppe;
    if (gruppe === 'fix') throw new HttpFehler(403, 'Fixkosten legt nur der Besitzer an.', { feld: 'gruppe' });
    if (gruppe === 'reisekasse') throw new HttpFehler(400, 'Reisekosten (Campingplatz, Essen, Souvenirs) bleiben bei dir und gehen nicht ins Fahrzeug.', { feld: 'gruppe' });
    if (!GAST_KOSTENARTEN[gruppe]) throw new HttpFehler(400, 'Bitte wählen: variable Kosten oder Instandhaltung.', { feld: 'gruppe' });
    let kostenart = null;
    if (b.kostenart !== undefined && b.kostenart !== null && b.kostenart !== '') {
      if (!GAST_KOSTENARTEN[gruppe].includes(b.kostenart)) throw new HttpFehler(400, 'Diese Art der Kosten gibt es in dieser Gruppe nicht.', { feld: 'kostenart' });
      kostenart = b.kostenart;
    }
    const bez = gastText(b.bezeichnung, 'bezeichnung', MAX_BEZEICHNUNG, true, 'Bitte kurz sagen, wofür der Betrag ist, zum Beispiel „Diesel“ oder „Maut“.');
    const betrag = Math.round(gastZahl(b.betrag, 'betrag', 0.01, 10000000, 'Bitte einen Betrag über 0 eingeben.') * 100) / 100;
    const datum = gastDatum(b.datum, jetzt);
    const ort = gastText(b.ortText, 'ortText', 120, false);
    const id = neueKennung('ko'), vid = neueKennung('vl');
    const werte = { bezeichnung: bez, kostenart, betrag, datum, gruppe, rhythmus: 'einmalig', bis: null, grundlage: 'eingegeben', waehrung: null, betragWaehrung: null, ortText: ort,
      komponenteId: null, aktivitaetId: null, ortId: null, abschnittId: null, besuchId: null, vorgangId: null, ausgeblendet: 'nein' };
    liste.push({ tabelle: 'kosten', id, fahrzeugId: fzId, objekt: { id, datenraumId: fz.datenraumId || null, fahrzeugId: fzId, erstelltAm: zeit, gast: marke } },
      { tabelle: 'verlaeufe', id: vid, fahrzeugId: null, objekt: { id: vid, objektTyp: 'kosten', objektId: id, nr: 1, werte, quelle: 'hand', korrekturZu: null, erstelltAm: zeit, gast: marke } });
  } else if (art === 'stoerung') {
    const bez = gastText(b.bezeichnung, 'bezeichnung', MAX_BEZEICHNUNG, true, 'Bitte kurz sagen, worum es geht, zum Beispiel „Motor springt schlecht an“.');
    const beschr = gastText(b.beschreibung, 'beschreibung', MAX_BESCHREIBUNG, false);
    if (!GAST_AUSWIRKUNGEN.includes(b.auswirkung)) throw new HttpFehler(400, 'Bitte wählen, wie weit die Störung das Fahrzeug einschränkt.', { feld: 'auswirkung' });
    const id = neueKennung('vg'), vid = neueKennung('vl');
    const werte = { bezeichnung: bez, beschreibung: beschr, auswirkung: b.auswirkung, gemeldetAm: datumText(jetzt), ausfuehrung: null, arbeit: null, adresseId: null, art: 'stoerung', status: 'offen', erledigtAm: null };
    liste.push({ tabelle: 'vorgaenge', id, fahrzeugId: fzId, objekt: { id, fahrzeugId: fzId, komponenteId: null, erstelltAm: zeit, gast: marke } },
      { tabelle: 'verlaeufe', id: vid, fahrzeugId: null, objekt: { id: vid, objektTyp: 'vorgang', objektId: id, nr: 1, werte, quelle: 'hand', korrekturZu: null, erstelltAm: zeit, gast: marke } });
  } else {
    throw new HttpFehler(400, 'Diese Art von Eintrag gibt es nicht. Möglich sind Kilometer, Kosten und Störung.', { feld: 'art' });
  }
  await abgleichNeu(db, dr, liste, jetzt);
  if (art === 'stoerung') return { ok: true, id: liste[0].id, mail: await stoerungMailen(env, db, f, a, liste[1].objekt.werte, jetzt) };
  return { ok: true, id: liste[0].id };
}

/* 13f-3: Info-Mail an den Besitzer, wenn ein Gast eine Störung meldet. Nur zur Information. Ein Fehler hier darf die Meldung nie verhindern,
   sie ist schon gespeichert. Höchstens 5 Mails je Freigabe und Stunde. Die Mail nennt nichts, was der Besitzer nicht ohnehin sieht. */
const MAX_STOERUNG_MAILS = 5;
export const STOERUNG_AUSWIRKUNG_TEXT = { keine: 'Das Fahrzeug bleibt nutzbar.', bedingt: 'Das Fahrzeug ist nur bedingt einsatzfähig.', nicht: 'Das Fahrzeug ist nicht einsatzfähig.' };
async function stoerungMailen(env, db, f, gast, werte, jetzt) {
  try {
    await bremsen(db, await schluesselFuer('gast-m', f.id), MAX_STOERUNG_MAILS, 60 * MINUTE, jetzt, 'Zu viele Mails.');
    const o = await db.prepare('SELECT n.email AS email FROM datenraum d JOIN nutzer n ON n.id = d.nutzer_id WHERE d.id = ?').bind(f.datenraum_id).first();
    if (!o || !o.email) return false;
    const n = await db.prepare("SELECT json_extract(e.nutzlast, '$.werte.bezeichnung') AS name FROM abgleich e WHERE e.datenraum_id = ? AND e.tabelle = 'eintraege' AND e.fahrzeug_id = ? AND e.geloescht = 0 ORDER BY json_extract(e.nutzlast, '$.nr') DESC LIMIT 1").bind(f.datenraum_id, f.fahrzeug_id).first();
    const fahrzeug = (n && n.name) || 'dein Fahrzeug';
    const wer = f.gast_name || gast.email;
    const text = wer + ' hat an „' + fahrzeug + '“ eine Störung gemeldet.\n\n' + werte.bezeichnung + (werte.beschreibung ? '\n' + werte.beschreibung : '') + '\n\n' + (STOERUNG_AUSWIRKUNG_TEXT[werte.auswirkung] || '') +
      '\n\nDie Störung steht in MobiMory unter Werkstatt (nach dem nächsten Abgleich). Diese Mail ist nur zur Information, du musst nichts tun und sie nicht beantworten.';
    const r = await mailSenden(env, o.email, 'MobiMory: Störung an „' + fahrzeug + '“ gemeldet', text);
    return !!(r && r.gesendet);
  } catch (e) { return false; }
}

/* Kontroll-Code durch den Gast (Campingplatz, Kontrolle unterwegs): nur mit „mitnutzen“, nie länger als die Freigabe. */
async function geteiltKontrolle(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  const f = await gastFreigabe(db, a, b.freigabe, jetzt, true);
  if (f.rechte !== 'mitnutzen') throw new HttpFehler(403, 'Diese Freigabe erlaubt nur das Ansehen. Der Besitzer kann dir die Mitnutzung geben.');
  const stunden = b.stunden === undefined || b.stunden === null ? KONTROLLE_STANDARD_STUNDEN : b.stunden;
  if (!Number.isInteger(stunden) || stunden < 1 || stunden > KONTROLLE_MAX_STUNDEN) throw new HttpFehler(400, 'Die Gültigkeit liegt zwischen 1 Stunde und ' + KONTROLLE_MAX_STUNDEN + ' Stunden (7 Tage).', { feld: 'stunden' });
  if (!(await fahrzeugDa(db, f.datenraum_id, f.fahrzeug_id))) throw new HttpFehler(404, 'Dieses Fahrzeug wird nicht mehr geteilt.');
  await bremsen(db, await schluesselFuer('gast-k', a.id), 20, 60 * MINUTE, jetzt, 'Du hast in kurzer Zeit zu viele Codes erzeugt.');
  const offen = await db.prepare('SELECT COUNT(*) AS n FROM kontrolle WHERE datenraum_id = ? AND widerrufen_am IS NULL AND laeuft_ab > ?').bind(f.datenraum_id, jetzt).first();
  if (offen && offen.n >= MAX_KONTROLLEN) throw new HttpFehler(409, 'Es gibt schon ' + MAX_KONTROLLEN + ' gültige Kontroll-Codes. Bitte den Besitzer fragen.');
  const code = zufallCode(KONTROLLE_CODE_LAENGE), id = crypto.randomUUID(), laeuftAb = Math.min(jetzt + stunden * 60 * MINUTE, f.laeuft_ab);
  await db.prepare('INSERT INTO kontrolle (id, datenraum_id, fahrzeug_id, code_hash, erstellt_am, laeuft_ab) VALUES (?, ?, ?, ?, ?, ?)').bind(id, f.datenraum_id, f.fahrzeug_id, await codeAbdruck(env, 'kontrolle', code), jetzt, laeuftAb).run();
  return { ok: true, id, code, laeuftAb, stunden };
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
  let rollen = false;
  try { await datenbank(env).prepare('SELECT 1 FROM rolle LIMIT 1').first(); rollen = true; } catch (e) { rollen = false; }
  let verleih = false;
  try { await datenbank(env).prepare('SELECT nachweis_art, nachweis_bis, bestaetigt_am FROM freigabe LIMIT 1').first(); verleih = true; } catch (e) { verleih = false; }
  let mitnutzung = false;
  try { await datenbank(env).prepare('SELECT rechte, gast_name, ausnahmen FROM freigabe LIMIT 1').first(); mitnutzung = true; } catch (e) { mitnutzung = false; }
  let planung = false;
  try { await datenbank(env).prepare('SELECT plan_ab FROM freigabe LIMIT 1').first(); planung = true; } catch (e) { planung = false; }
  let waechter = false;
  try { await datenbank(env).prepare('SELECT 1 FROM waechter_stand LIMIT 1').first(); waechter = !!(env && env.EMAIL && env.ABSENDER && waechterEmpfaenger(env)); } catch (e) { waechter = false; }
  /* Bezahlung (13e-4): die Tabellen und was im Worker eingetragen ist. Es steht nur „ja“ oder „nein“ da, nie ein Wert. */
  let bezTabellen = false;
  try { const db = datenbank(env); for (const t of ['bestellung', 'beleg', 'check_extra', 'erinnerung', 'zaehler']) await db.prepare('SELECT 1 FROM ' + t + ' LIMIT 1').first(); bezTabellen = true; } catch (e) { bezTabellen = false; }
  let routenTab = false;
  try { const db = datenbank(env); await db.prepare('SELECT 1 FROM route_nutzung LIMIT 1').first(); await db.prepare('SELECT 1 FROM route_extra LIMIT 1').first(); routenTab = true; } catch (e) { routenTab = false; }
  let lesenTab = false;
  try { await datenbank(env).prepare('SELECT 1 FROM lese_nutzung LIMIT 1').first(); lesenTab = true; } catch (e) { lesenTab = false; }
  let gutscheine = false;
  try { const db = datenbank(env); await db.prepare('SELECT 1 FROM gutschein LIMIT 1').first(); await db.prepare('SELECT 1 FROM gutschein_einloesung LIMIT 1').first(); await db.prepare('SELECT gutschein, liste_cent FROM bestellung LIMIT 1').first(); await db.prepare('SELECT gutschein, liste_cent FROM beleg LIMIT 1').first(); gutscheine = true; } catch (e) { gutscheine = false; }
  const bezahlung = { tabellen: bezTabellen, gutscheine, paypal: paypalEingerichtet(env), paypalEchtgeld: !!(env && env.PAYPAL_LIVE === '1'), ueberweisung: !!ueberweisungDaten(env), freischalten: !!adminToken(env), beleg: !!belegAnschrift(env) };
  return {
    ok: true, dienst: DIENST, version: VERSION, app: { mindestversion: appMindestversion(env) },
    datenbank: !!(env && env.DB), tabellen, abgleich, dateien, freigaben, stufen, rollen, verleih, mitnutzung, planung, stoerungsmail: true, waechter,
    routen: { tabellen: routenTab, schluessel: !!(env && typeof env.HERE_SCHLUESSEL === 'string' && env.HERE_SCHLUESSEL.trim().length >= 8) },
    lesen: { tabelle: lesenTab, schluessel: !!(env && typeof env.GOOGLE_VISION_KEY === 'string' && env.GOOGLE_VISION_KEY.trim().length >= 8) },
    recherche: !!(env && typeof env.RECHERCHE_URL === 'string' && /^https:\/\//.test(env.RECHERCHE_URL) && typeof env.RECHERCHE_TOKEN === 'string' && env.RECHERCHE_TOKEN.length >= 8),
    pepper: typeof (env && env.PASSWORT_PEPPER) === 'string' && env.PASSWORT_PEPPER.length >= 32,
    mail: !!(env && env.EMAIL && env.ABSENDER),
    speicher: !!(env && env.DATEN),
    bezahlung: bezahlung,
    entwicklung: !!(env && env.ENTWICKLUNG === '1')
  };
}


/* ---------- 13e: Stufen, Kontingent und Online-Checks ---------- */

/* Die Zahlen sind Richtwerte (Nutzer, 12.11.2026). Sie stehen nur hier und in js/konto.js (ein Test vergleicht beide). */
export const STUFEN = {
  basic: { name: 'Basic', geraete: 2, checks: 0, routen: 0, fahrzeuge: 1, online: false, scans: 0 },
  test: { name: 'Testwoche', geraete: 4, checks: 1, routen: 10, fahrzeuge: 3, online: true, scans: 10 },
  mittel: { name: 'Mittel', geraete: 4, checks: 3, routen: 100, fahrzeuge: 3, online: true, scans: 50 },
  voll: { name: 'Voll', geraete: 10, checks: 10, routen: 1000, fahrzeuge: null, online: true, scans: 100 },
  /* Nur für den Entwickler, nur per SQL setzbar, keine Grenzen (null = unbegrenzt). Nur die Bremse gegen zu viele Checks hintereinander bleibt. */
  entwickler: { name: 'Entwickler', geraete: null, checks: null, routen: null, fahrzeuge: null, online: true, scans: null }
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
  try { await db.prepare('DELETE FROM route_nutzung WHERE am <= ? OR (status = ? AND am <= ?)').bind(jetzt - (CHECK_ZEITRAUM_TAGE + 35) * TAG, 'laeuft', jetzt - 1 * TAG).run(); } catch (e) { if (!fehltTabelle(e)) throw e; }
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

/* Nachgekaufte Recherchen (seit 2.0.72): Tabelle check_extra. Fehlt sie noch, gibt es keine. */
async function extraFrei(db, nutzerId) {
  try {
    const z = await db.prepare('SELECT anzahl FROM check_extra WHERE nutzer_id = ?').bind(nutzerId).first();
    return z ? z.anzahl : 0;
  } catch (e) { if (fehltTabelle(e)) return 0; throw e; }
}
async function extraNehmen(db, nutzerId) {
  try {
    const r = await db.prepare('UPDATE check_extra SET anzahl = anzahl - 1 WHERE nutzer_id = ? AND anzahl > 0').bind(nutzerId).run();
    return !!(r && r.meta && r.meta.changes === 1);
  } catch (e) { if (fehltTabelle(e)) return false; throw e; }
}
async function extraZurueck(db, nutzerId) {
  try { await db.prepare('UPDATE check_extra SET anzahl = anzahl + 1 WHERE nutzer_id = ?').bind(nutzerId).run(); } catch (e) { /* nächster Versuch beim Support */ }
}

/* ---------- 13f-10: Routenplanung (seit 2.0.88) ---------- */

/* Zählung wie bei den Online-Checks, aber getrennt davon (Tabellen route_nutzung und route_extra). Fehlen die Tabellen, gibt es nichts Gezähltes und nichts Nachgekauftes. */
async function routenGenutzt(db, dr, stufeId, jetzt) {
  try {
    const klasse = stufeId === 'test' ? ['test'] : (stufeId === 'entwickler' ? ['entwickler'] : ['mittel', 'voll']);
    const z = await db.prepare('SELECT COUNT(*) AS n FROM route_nutzung WHERE datenraum_id = ? AND am > ? AND status IN (?, ?) AND stufe IN (?, ?)')
      .bind(dr, jetzt - CHECK_ZEITRAUM_TAGE * TAG, 'laeuft', 'ok', klasse[0], klasse[1] || klasse[0]).first();
    return z ? z.n : 0;
  } catch (e) { if (fehltTabelle(e)) return 0; throw e; }
}
async function routenExtraFrei(db, nutzerId) {
  try {
    const z = await db.prepare('SELECT anzahl FROM route_extra WHERE nutzer_id = ?').bind(nutzerId).first();
    return z ? z.anzahl : 0;
  } catch (e) { if (fehltTabelle(e)) return 0; throw e; }
}
async function routenExtraNehmen(db, nutzerId) {
  try {
    const r = await db.prepare('UPDATE route_extra SET anzahl = anzahl - 1 WHERE nutzer_id = ? AND anzahl > 0').bind(nutzerId).run();
    return !!(r && r.meta && r.meta.changes === 1);
  } catch (e) { if (fehltTabelle(e)) return false; throw e; }
}
async function routenExtraZurueck(db, nutzerId) {
  try { await db.prepare('UPDATE route_extra SET anzahl = anzahl + 1 WHERE nutzer_id = ?').bind(nutzerId).run(); } catch (e) { /* nächster Versuch beim Support */ }
}

const HERE_URL = 'https://router.hereapi.com/v8/routes';
const ZEIT_HERE_MS = 30 * 1000;
/* Seit 2.0.123: bis 25 Zwischenziele (die App prüft die Zahl der Tage; der Dienst kennt sie nicht). */
const MAX_VIA = 25;
const MAX_ROUTE_PUNKTE = 3000;

/* Die Positionen aus der Anfrage: { breite, laenge } oder Fehler. */
function routePunkt(p, feld) {
  const b = p && typeof p === 'object' ? Number(p.breite) : NaN, l = p && typeof p === 'object' ? Number(p.laenge) : NaN;
  if (!(b >= -90 && b <= 90) || !(l >= -180 && l <= 180) || (p.breite === null || p.laenge === null)) throw new HttpFehler(400, 'Die Position von ' + feld + ' fehlt oder ist ungültig.', { feld });
  return { breite: Math.round(b * 100000) / 100000, laenge: Math.round(l * 100000) / 100000 };
}
/* Maße in Metern, Gewichte in Kilogramm (Angaben aus dem Fahrzeug). HERE rechnet Maße in Zentimetern. Fehlende Angaben bleiben weg. */
function routeFahrzeug(f) {
  const q = f && typeof f === 'object' ? f : {};
  const z = (v, min, max) => { const n = Number(v); return v !== null && v !== undefined && v !== '' && isFinite(n) && n >= min && n <= max ? n : null; };
  const o = { hoehe: z(q.hoehe, 0.5, 6), breite: z(q.breite, 0.5, 5), laenge: z(q.laenge, 1, 40), gesamtgewicht: z(q.gesamtgewicht, 100, 100000), achslast: z(q.achslast, 100, 30000), achsen: z(q.achsen, 1, 10) };
  return o;
}

/* HERE liefert die Linie als „flexible polyline“. Dekodieren ohne Zusatzpaket (2D, die Höhe wird übersprungen). */
export function polylineDekodieren(text) {
  const tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const pos = { i: 0 };
  const wert = () => {
    let r = 0, schub = 0, c;
    for (;;) {
      if (pos.i >= text.length) throw new Error('Linie unvollständig');
      c = tab.indexOf(text[pos.i++]);
      if (c < 0) throw new Error('Linie ungültig');
      r |= (c & 31) << schub; schub += 5;
      if (!(c & 32)) break;
    }
    return r;
  };
  const vz = (n) => (n & 1 ? ~(n >> 1) : n >> 1);
  const kopf = wert(); if (kopf !== 1) throw new Error('Linienformat unbekannt');
  const bits = wert();
  const genau = bits & 15, dritte = (bits >> 4) & 7;
  const f = Math.pow(10, genau);
  const aus = [];
  let b = 0, l = 0;
  while (pos.i < text.length) {
    b += vz(wert()); l += vz(wert());
    if (dritte) wert();
    aus.push({ breite: b / f, laenge: l / f });
  }
  return aus;
}

function ausduennen(punkte, max) {
  if (punkte.length <= max) return punkte;
  const schritt = (punkte.length - 1) / (max - 1);
  const r = [];
  for (let i = 0; i < max; i++) r.push(punkte[Math.round(i * schritt)]);
  return r;
}

/* Aus der Antwort von HERE: Punkte, Länge (km), Dauer (Minuten), Warnungen. Wirft HttpFehler, wenn es keine Route gibt. */
export function routeAuswerten(j) {
  const route = j && Array.isArray(j.routes) ? j.routes[0] : null;
  if (!route || !Array.isArray(route.sections) || !route.sections.length) {
    const nr = j && Array.isArray(j.notices) && j.notices.some((n) => n && n.code === 'noRouteFound');
    throw new HttpFehler(404, nr || (j && j.routes) ? 'Zwischen diesen Orten wurde keine Route für dieses Fahrzeug gefunden. Dieser Versuch wurde nicht gezählt.' : 'Der Routen-Dienst hat keine Route geliefert. Dieser Versuch wurde nicht gezählt.');
  }
  let punkte = [], meter = 0, sek = 0;
  const warnungen = [], gesehen = {};
  for (const s of route.sections) {
    if (typeof s.polyline !== 'string') continue;
    const basis = punkte.length;
    let pl;
    try { pl = polylineDekodieren(s.polyline); } catch (e) { throw new HttpFehler(502, 'Die Route des Routen-Dienstes ist nicht lesbar. Dieser Versuch wurde nicht gezählt.'); }
    punkte = punkte.concat(pl);
    if (s.summary) { meter += Number(s.summary.length) || 0; sek += Number(s.summary.duration) || 0; }
    const notices = Array.isArray(s.notices) ? s.notices : [];
    const spans = Array.isArray(s.spans) ? s.spans : [];
    notices.forEach((n, idx) => {
      if (!n || typeof n !== 'object') return;
      const code = String(n.code || ''), stufe = n.severity === 'critical' ? 'kritisch' : 'hinweis';
      if (code === 'noRouteFound') return;
      let ort = null;
      for (const sp of spans) { if (Array.isArray(sp.notices) && sp.notices.includes(idx) && typeof sp.offset === 'number' && pl[sp.offset]) { ort = pl[sp.offset]; break; } }
      const schl = code + ':' + stufe + ':' + (ort ? ort.breite.toFixed(3) + ',' + ort.laenge.toFixed(3) : '');
      if (gesehen[schl]) return; gesehen[schl] = 1;
      const einzel = Array.isArray(n.details) ? n.details.map((d) => d && typeof d.cause === 'string' ? d.cause : '').filter(Boolean)[0] : '';
      warnungen.push({ code: code.slice(0, 60), stufe, titel: String(n.title || '').slice(0, 160), grund: String(einzel || '').slice(0, 200), ort });
    });
  }
  if (punkte.length < 2) throw new HttpFehler(502, 'Der Routen-Dienst hat keine Linie geliefert. Dieser Versuch wurde nicht gezählt.');
  return { punkte: ausduennen(punkte, MAX_ROUTE_PUNKTE).map((p) => ({ breite: Math.round(p.breite * 100000) / 100000, laenge: Math.round(p.laenge * 100000) / 100000 })),
    laengeKm: Math.round(meter / 10) / 100, dauerMin: Math.round(sek / 60), warnungen: warnungen.slice(0, 30) };
}

/* Eine Route planen: Anmeldung, Stufe und Kontingent prüfen, zählen, HERE fragen. Schlägt HERE fehl oder gibt es keine Route, wird nicht gezählt. */
async function routePlanen(request, env, db, jetzt, optionen) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request, 32 * 1024);
  const von = routePunkt(b.von, 'von'), nach = routePunkt(b.nach, 'nach');
  const via = (Array.isArray(b.via) ? b.via : []).slice(0, MAX_VIA).map((p, i) => routePunkt(p, 'via'));
  if (Array.isArray(b.via) && b.via.length > MAX_VIA) throw new HttpFehler(400, 'Es sind höchstens ' + MAX_VIA + ' Zwischenziele möglich.', { feld: 'via' });
  const fz = routeFahrzeug(b.fahrzeug);
  if (!a.datenraumId) throw new HttpFehler(400, 'Zu diesem Konto gehört noch kein Datenraum.');
  const st = await stufeVon(db, a.id, jetzt, false);
  if (!st.grenzen.online || st.grenzen.routen === 0) throw new HttpFehler(402, 'Die Routenplanung gibt es ab der Stufe Mittel oder in der Testwoche. Deine Stufe ist ' + st.name + '.', { stufe: st.id });
  const schluessel = env && typeof env.HERE_SCHLUESSEL === 'string' ? env.HERE_SCHLUESSEL.trim() : '';
  if (schluessel.length < 8) throw new HttpFehler(503, 'Der Routen-Dienst ist im Konto-Dienst noch nicht eingetragen.');
  await bremsen(db, await schluesselFuer('rte', a.datenraumId), 10, 10 * MINUTE, jetzt, 'Es wurden zu viele Routen hintereinander geplant.');
  const genutzt = await routenGenutzt(db, a.datenraumId, st.id, jetzt);
  let extraGenommen = false;
  if (st.grenzen.routen !== null && genutzt >= st.grenzen.routen) {
    extraGenommen = await routenExtraNehmen(db, a.id);
    if (!extraGenommen) throw new HttpFehler(402, 'Dein Kontingent ist aufgebraucht: ' + genutzt + ' von ' + st.grenzen.routen + ' geplanten Routen in den letzten 12 Monaten. Unter Konto kannst du 100 zusätzliche Routen kaufen.', { genutzt, grenze: st.grenzen.routen, stufe: st.id });
  }
  const nid = crypto.randomUUID();
  try {
    await db.prepare('INSERT INTO route_nutzung (id, datenraum_id, stufe, am, status) VALUES (?, ?, ?, ?, ?)').bind(nid, a.datenraumId, extraGenommen ? 'extra' : st.id, jetzt, 'laeuft').run();
  } catch (e) { if (extraGenommen) await routenExtraZurueck(db, a.id); throw e; }
  async function zurueck() {
    try { await db.prepare('DELETE FROM route_nutzung WHERE id = ?').bind(nid).run(); } catch (e) { /* wird später aufgeräumt */ }
    if (extraGenommen) await routenExtraZurueck(db, a.id);
  }
  const pt = (p) => p.breite + ',' + p.laenge;
  const q = ['transportMode=truck', 'origin=' + pt(von), 'destination=' + pt(nach), 'return=polyline,summary', 'spans=notices', 'lang=de'];
  via.forEach((p) => q.push('via=' + pt(p)));
  if (fz.hoehe !== null) q.push('vehicle[height]=' + Math.round(fz.hoehe * 100));
  if (fz.breite !== null) q.push('vehicle[width]=' + Math.round(fz.breite * 100));
  if (fz.laenge !== null) q.push('vehicle[length]=' + Math.round(fz.laenge * 100));
  if (fz.gesamtgewicht !== null) q.push('vehicle[grossWeight]=' + Math.round(fz.gesamtgewicht));
  if (fz.achslast !== null) q.push('vehicle[weightPerAxle]=' + Math.round(fz.achslast));
  if (fz.achsen !== null) q.push('vehicle[axleCount]=' + Math.round(fz.achsen));
  const holen = (optionen && optionen.fetch) || fetch;
  let r, text;
  try {
    const ctl = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), ZEIT_HERE_MS) : null;
    try {
      r = await holen(HERE_URL + '?' + q.join('&') + '&apiKey=' + encodeURIComponent(schluessel), { method: 'GET', signal: ctl ? ctl.signal : undefined });
      text = await r.text();
    } finally { if (timer) clearTimeout(timer); }
  } catch (e) {
    await zurueck();
    throw new HttpFehler(502, 'Der Routen-Dienst hat nicht rechtzeitig geantwortet. Dieser Versuch wurde nicht gezählt.');
  }
  let j = null;
  try { j = JSON.parse(text); } catch (e) { j = null; }
  if (!r.ok || !j || typeof j !== 'object') {
    await zurueck();
    throw new HttpFehler(502, 'Der Routen-Dienst konnte die Route nicht berechnen (Antwort ' + (r && r.status) + '). Dieser Versuch wurde nicht gezählt.');
  }
  let erg;
  try { erg = routeAuswerten(j); } catch (e) { await zurueck(); throw e; }
  await db.prepare('UPDATE route_nutzung SET status = ? WHERE id = ?').bind('ok', nid).run();
  const kontingent = { genutzt: extraGenommen ? genutzt : genutzt + 1, grenze: st.grenzen.routen, stufe: st.id };
  if (extraGenommen) kontingent.extraFrei = await routenExtraFrei(db, a.id);
  return { ok: true, route: erg, kontingent, fahrzeugAngaben: fz };
}

/* ---------- 13h: Alarm-Nachrichten an die angemeldeten Geräte (seit 2.0.120) ----------
   Ein Gerät (die Wache) meldet „Alarm“. Der Dienst schickt an alle ANDEREN Geräte des Kontos eine Push-Nachricht und an die E-Mail-Adresse des Kontos
   eine E-Mail. Der Text ist allgemein gehalten und enthält keine Position und keinen Fahrzeugnamen: Er geht über die Dienste von Google, Mozilla und Apple.
   Web-Push (Browser, Tablet): VAPID-Schlüssel (Geheimnisse VAPID_PRIVAT als JWK-Text und VAPID_OEFFENTLICH), Nachricht ohne Inhalt, die App holt den Text selbst.
   Android-Hülle: Firebase Cloud Messaging (Geheimnis FCM_KONTO = Dienstkonto-Schlüssel als JSON-Text). */

const PUSH_DIENSTE = ['fcm.googleapis.com', 'updates.push.services.mozilla.com', 'push.apple.com', 'notify.windows.com', 'push.services.mozilla.com'];
const ALARM_TEXT = { titel: 'MobiMory: Alarm', text: 'Eine deiner Wachen hat ausgelöst. Bitte MobiMory öffnen.' };
const TEST_TEXT = { titel: 'MobiMory: Test', text: 'Das ist eine Test-Nachricht. Es ist kein Alarm.' };

function pushZielOk(art, ziel) {
  if (typeof ziel !== 'string' || !ziel) return false;
  if (art === 'fcm') return /^[A-Za-z0-9_:\-.]{20,4096}$/.test(ziel);
  if (art !== 'web' || ziel.length > 1000) return false;
  let u;
  try { u = new URL(ziel); } catch (e) { return false; }
  if (u.protocol !== 'https:' || u.username || u.password || u.port) return false;
  return PUSH_DIENSTE.some((d) => u.hostname === d || u.hostname.endsWith('.' + d));
}

async function pushAnmelden(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  const geraet = typeof b.geraet === 'string' ? b.geraet : '';
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(geraet)) throw new HttpFehler(400, 'Die Gerätekennung ist ungültig.', { feld: 'geraet' });
  if (!pushZielOk(b.art, b.ziel)) throw new HttpFehler(400, 'Diese Push-Adresse nimmt der Dienst nicht an.', { feld: 'ziel' });
  await db.prepare('INSERT INTO push_ziel (id, nutzer_id, geraet, art, ziel, erstellt_am) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(nutzer_id, geraet) DO UPDATE SET art = excluded.art, ziel = excluded.ziel, erstellt_am = excluded.erstellt_am')
    .bind('pz' + zuBase64Url(zufall(9)), a.id, geraet, b.art, b.ziel, jetzt).run();
  return { ok: true };
}

async function pushAbmelden(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  const geraet = typeof b.geraet === 'string' ? b.geraet : '';
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(geraet)) throw new HttpFehler(400, 'Die Gerätekennung ist ungültig.', { feld: 'geraet' });
  await db.prepare('DELETE FROM push_ziel WHERE nutzer_id = ? AND geraet = ?').bind(a.id, geraet).run();
  return { ok: true };
}

async function pushSchluessel(request, env, db, jetzt) {
  await authentifizieren(request, db, jetzt);
  return { ok: true, vapid: env.VAPID_OEFFENTLICH || null, fcm: !!env.FCM_KONTO };
}

const textBytes = (t) => new TextEncoder().encode(t);

async function vapidKopf(env, endpoint, jetzt) {
  const jwk = JSON.parse(env.VAPID_PRIVAT);
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const kopf = zuBase64Url(textBytes(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const inhalt = zuBase64Url(textBytes(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(jetzt / 1000) + 12 * 3600, sub: 'mailto:' + (env.ABSENDER_ADRESSE || 'info@mobimory.com') })));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, textBytes(kopf + '.' + inhalt)));
  return 'vapid t=' + kopf + '.' + inhalt + '.' + zuBase64Url(sig) + ', k=' + env.VAPID_OEFFENTLICH;
}

async function webPushSenden(env, ziel, jetzt) {
  const r = await fetch(ziel, { method: 'POST', headers: { Authorization: await vapidKopf(env, ziel, jetzt), TTL: '3600', Urgency: 'high', 'Content-Length': '0' } });
  return { ok: r.status >= 200 && r.status < 300, weg: r.status === 404 || r.status === 410, status: r.status };
}

async function fcmToken(env, jetzt) {
  const k = JSON.parse(env.FCM_KONTO);
  const pem = String(k.private_key).replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  const key = await crypto.subtle.importKey('pkcs8', ausBase64Url(pem.replace(/\+/g, '-').replace(/\//g, '_')), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const jetztS = Math.floor(jetzt / 1000);
  const kopf = zuBase64Url(textBytes(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const inhalt = zuBase64Url(textBytes(JSON.stringify({ iss: k.client_email, scope: 'https://www.googleapis.com/auth/firebase.messaging', aud: 'https://oauth2.googleapis.com/token', iat: jetztS, exp: jetztS + 3000 })));
  const sig = zuBase64Url(new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, textBytes(kopf + '.' + inhalt))));
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + kopf + '.' + inhalt + '.' + sig });
  if (!r.ok) throw new Error('FCM-Anmeldung abgelehnt');
  return { token: (await r.json()).access_token, projekt: k.project_id };
}

async function fcmSenden(env, t, ziel, text) {
  text = text || ALARM_TEXT;
  const r = await fetch('https://fcm.googleapis.com/v1/projects/' + encodeURIComponent(t.projekt) + '/messages:send', {
    method: 'POST', headers: { Authorization: 'Bearer ' + t.token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: { token: ziel, notification: { title: text.titel, body: text.text }, android: { priority: 'HIGH', notification: { channel_id: 'alarm' } }, data: { art: text === TEST_TEXT ? 'test' : 'alarm' } } }) });
  return { ok: r.ok, weg: r.status === 404, status: r.status };
}

async function alarmSenden(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request);
  const eigenes = typeof b.geraet === 'string' && /^[A-Za-z0-9_-]{4,64}$/.test(b.geraet) ? b.geraet : '';
  await bremsen(db, 'alarm:' + a.id, 12, 10 * MINUTE, jetzt, 'Es wurden zu viele Alarme gesendet. Bitte warte einige Minuten.');
  const r = await db.prepare('SELECT id, geraet, art, ziel FROM push_ziel WHERE nutzer_id = ?').bind(a.id).all();
  const ziele = ((r && r.results) || []).filter((z) => z.geraet !== eigenes);
  const test = b.test === true;
  let gesendet = 0, fehler = 0, fcmT = null;
  const grund = [];
  for (const z of ziele) {
    try {
      let e;
      if (z.art === 'web' && env.VAPID_PRIVAT && env.VAPID_OEFFENTLICH) e = await webPushSenden(env, z.ziel, jetzt);
      else if (z.art === 'fcm' && env.FCM_KONTO) { if (!fcmT) fcmT = await fcmToken(env, jetzt); e = await fcmSenden(env, fcmT, z.ziel, test ? TEST_TEXT : ALARM_TEXT); }
      else { fehler++; grund.push(z.art + ': Schlüssel beim Dienst fehlt'); continue; }
      if (e.ok) gesendet++; else { fehler++; grund.push(z.art + ' ' + (e.status || '?')); }
      if (e.weg) await db.prepare('DELETE FROM push_ziel WHERE id = ?').bind(z.id).run();
    } catch (err) { fehler++; grund.push(z.art + ': ' + (z.art === 'fcm' && String(err && err.message).indexOf('FCM-Anmeldung') === 0 ? 'Anmeldung bei Google abgelehnt (FCM_KONTO prüfen)' : 'Fehler')); }
  }
  if (test) return { ok: true, push: gesendet, fehler, mail: false, ziele: ziele.length, grund };
  let mail = false;
  try {
    const m = await mailSenden(env, a.email, ALARM_TEXT.titel, ALARM_TEXT.text + '\n\nDiese Nachricht kommt von einer Wache in deinem MobiMory-Konto.');
    mail = !!m.gesendet;
  } catch (err) { mail = false; }
  return { ok: true, push: gesendet, fehler, mail, ziele: ziele.length, grund };
}

/* ---------- 13g: Lesedienst für Smart Capture (seit 2.0.98) ---------- */

/* Festlegung des Nutzers (16.11.2026): Smart Capture liest das Foto beim Google-Dienst (Cloud Vision, EU-Adresse). Nur für Konten mit bezahlter Stufe
   (Mittel 50, Voll 100 Scans pro Konto und Monat; ein Foto = ein Scan, Vorder- und Rückseite zählen als zwei). Ein ermäßigter oder geschenkter Preis ändert
   die Grenze nicht, sie richtet sich nur nach der Stufe. Der Dienst speichert weder das Foto noch den Text, er zählt nur (Tabelle lese_nutzung).
   Der Zugangsschlüssel steht nur als Secret GOOGLE_VISION_KEY im Worker. Der Monat ist der Kalendermonat nach UTC. */
const VISION_URL = 'https://eu-vision.googleapis.com/v1/images:annotate';
const ZEIT_VISION_MS = 40 * 1000;
const MAX_LESEN_BILD = 3 * 1024 * 1024;         /* Zeichen der Base64-Schrift, rund 2,2 MB Bild */
const MAX_LESEN_WOERTER = 3000;
const MAX_LESEN_TEXT = 30000;

function monatVon(jetzt) { const d = new Date(jetzt); return { anfang: Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1), name: d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0') }; }

/* Wie viele Scans in diesem Monat gezählt sind (laufende und gelungene). Fehlt die Tabelle noch, ist es null. */
async function lesenGenutzt(db, dr, jetzt, stufeId) {
  try {
    /* Die Testwoche zählt über die ganze Woche (nur Scans, die in der Testwoche gemacht wurden), alle anderen Stufen je Kalendermonat. */
    const z = stufeId === 'test'
      ? await db.prepare('SELECT COUNT(*) AS n FROM lese_nutzung WHERE datenraum_id = ? AND stufe = ? AND status IN (?, ?)').bind(dr, 'test', 'laeuft', 'ok').first()
      : await db.prepare('SELECT COUNT(*) AS n FROM lese_nutzung WHERE datenraum_id = ? AND am >= ? AND status IN (?, ?)').bind(dr, monatVon(jetzt).anfang, 'laeuft', 'ok').first();
    return z ? z.n : 0;
  } catch (e) { if (fehltTabelle(e)) return 0; throw e; }
}

function bildPruefen(roh) {
  const b = typeof roh === 'string' ? roh.replace(/^data:[^,]*,/, '').replace(/\s+/g, '') : '';
  if (!b || b.length < 100) throw new HttpFehler(400, 'Es wurde kein Bild mitgeschickt.', { feld: 'bild' });
  if (b.length > MAX_LESEN_BILD) throw new HttpFehler(413, 'Das Bild ist zu groß.', { feld: 'bild' });
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b)) throw new HttpFehler(400, 'Das Bild ist nicht lesbar.', { feld: 'bild' });
  const kopf = b.slice(0, 8);
  /* JPEG beginnt mit FF D8 FF (Base64 „/9j/“), PNG mit 89 50 4E 47 (Base64 „iVBOR“) */
  if (!/^\/9j\//.test(kopf) && !/^iVBOR/.test(kopf)) throw new HttpFehler(400, 'Das Bild muss ein JPEG oder PNG sein.', { feld: 'bild' });
  return b;
}

/* Die Antwort von Google auf das Wesentliche kürzen: Wörter mit den vier Eckpunkten (x0,y0,x1,y1,x2,y2,x3,y3), Sicherheit 0 bis 100 und „Zeilenende“. */
export function visionAuswerten(j) {
  const r = j && Array.isArray(j.responses) ? j.responses[0] : null;
  if (!r || typeof r !== 'object') throw new HttpFehler(502, 'Der Lesedienst hat keine lesbare Antwort geschickt. Dieser Versuch wurde nicht gezählt.');
  if (r.error) throw new HttpFehler(502, 'Der Lesedienst konnte das Foto nicht lesen. Dieser Versuch wurde nicht gezählt.');
  const fa = r.fullTextAnnotation;
  const seite = fa && Array.isArray(fa.pages) ? fa.pages[0] : null;
  const woerter = [];
  let breite = 0, hoehe = 0;
  if (seite) {
    breite = Math.round(Number(seite.width) || 0); hoehe = Math.round(Number(seite.height) || 0);
    for (const bl of seite.blocks || []) for (const pa of bl.paragraphs || []) for (const wo of pa.words || []) {
      if (woerter.length >= MAX_LESEN_WOERTER) break;
      const sy = wo.symbols || [];
      const t = sy.map((x) => String(x.text || '')).join('').trim();
      if (!t) continue;
      const vs = wo.boundingBox && Array.isArray(wo.boundingBox.vertices) ? wo.boundingBox.vertices : [];
      if (vs.length < 4) continue;
      const v = [];
      for (let i = 0; i < 4; i++) { v.push(Math.round(Number(vs[i].x) || 0), Math.round(Number(vs[i].y) || 0)); }
      const letzte = sy.length ? sy[sy.length - 1] : null;
      const br = letzte && letzte.property && letzte.property.detectedBreak ? letzte.property.detectedBreak.type : '';
      const k = typeof wo.confidence === 'number' ? Math.max(0, Math.min(100, Math.round(wo.confidence * 100))) : 50;
      woerter.push({ t: t.slice(0, 80), v, k, e: br === 'EOL_SURE_SPACE' || br === 'LINE_BREAK' ? 1 : 0 });
    }
  }
  return { text: fa && typeof fa.text === 'string' ? fa.text.slice(0, MAX_LESEN_TEXT) : '', breite, hoehe, woerter };
}

async function lesenSenden(request, env, db, jetzt, optionen) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request, MAX_LESEN_BILD + 4096);
  if (b.zustimmung !== true) throw new HttpFehler(400, 'Ohne deine Zustimmung wird kein Foto zum Lesen gesendet.', { feld: 'zustimmung' });
  const bild = bildPruefen(b.bild);
  if (!a.datenraumId) throw new HttpFehler(400, 'Zu diesem Konto gehört noch kein Datenraum.');
  const st = await stufeVon(db, a.id, jetzt, false);
  const grenze = st.grenzen.scans;
  if (grenze === 0) throw new HttpFehler(402, 'Smart Capture gibt es mit der Stufe Mittel oder Voll. Deine Stufe ist ' + st.name + '.', { stufe: st.id, grund: 'stufe' });
  const schluessel = env && typeof env.GOOGLE_VISION_KEY === 'string' ? env.GOOGLE_VISION_KEY.trim() : '';
  if (schluessel.length < 8) throw new HttpFehler(503, 'Der Lesedienst ist im Konto-Dienst noch nicht eingetragen.');
  await bremsen(db, await schluesselFuer('les', a.datenraumId), 20, 10 * MINUTE, jetzt, 'Es wurden zu viele Fotos hintereinander gesendet.');
  const monat = monatVon(jetzt);
  const genutzt = await lesenGenutzt(db, a.datenraumId, jetzt, st.id);
  if (grenze !== null && genutzt >= grenze) {
    throw new HttpFehler(402, st.id === 'test' ? 'Deine Scans der Testwoche sind aufgebraucht: ' + genutzt + ' von ' + grenze + '. Mit Mittel oder Voll gibt es jeden Monat neue Scans. Bis dahin kannst du die Erkennung auf dem Gerät nehmen.' : 'Dein Kontingent für diesen Monat ist aufgebraucht: ' + genutzt + ' von ' + grenze + ' Scans. Ab dem 1. des nächsten Monats gibt es wieder neue. Bis dahin kannst du die Erkennung auf dem Gerät nehmen.', { genutzt, grenze, stufe: st.id, grund: 'limit', monat: monat.name });
  }
  const nid = crypto.randomUUID();
  await db.prepare('INSERT INTO lese_nutzung (id, datenraum_id, stufe, am, status) VALUES (?, ?, ?, ?, ?)').bind(nid, a.datenraumId, st.id, jetzt, 'laeuft').run();
  async function zurueck() { try { await db.prepare('DELETE FROM lese_nutzung WHERE id = ?').bind(nid).run(); } catch (e) { /* wird später aufgeräumt */ } }
  const holen = (optionen && optionen.fetch) || fetch;
  const koerper = JSON.stringify({ requests: [{ image: { content: bild }, features: [{ type: 'DOCUMENT_TEXT_DETECTION' }], imageContext: { languageHints: ['de'] } }] });
  let r, text;
  try {
    const ctl = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), ZEIT_VISION_MS) : null;
    try {
      r = await holen(VISION_URL + '?key=' + encodeURIComponent(schluessel), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: koerper, signal: ctl ? ctl.signal : undefined });
      text = await r.text();
    } finally { if (timer) clearTimeout(timer); }
  } catch (e) {
    await zurueck();
    throw new HttpFehler(502, 'Der Lesedienst hat nicht rechtzeitig geantwortet. Dieser Versuch wurde nicht gezählt.');
  }
  let j = null;
  try { j = JSON.parse(text); } catch (e) { j = null; }
  if (!r.ok || !j || typeof j !== 'object') {
    await zurueck();
    throw new HttpFehler(502, 'Der Lesedienst konnte das Foto nicht lesen (Antwort ' + (r && r.status) + '). Dieser Versuch wurde nicht gezählt.');
  }
  let erg;
  try { erg = visionAuswerten(j); } catch (e) { await zurueck(); throw e; }
  await db.prepare('UPDATE lese_nutzung SET status = ? WHERE id = ?').bind('ok', nid).run();
  return Object.assign({ ok: true }, erg, { kontingent: { genutzt: genutzt + 1, grenze, stufe: st.id, monat: monat.name } });
}

async function lesenAufraeumen(db, jetzt) {
  try { await db.prepare('DELETE FROM lese_nutzung WHERE am <= ? OR (status = ? AND am <= ?)').bind(jetzt - 400 * TAG, 'laeuft', jetzt - 1 * TAG).run(); } catch (e) { if (!fehltTabelle(e)) throw e; }
}

async function kontoStufe(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const st = await stufeVon(db, a.id, jetzt, false);
  const g = st.grenzen;
  const geraete = await db.prepare('SELECT COUNT(*) AS n FROM sitzung WHERE nutzer_id = ? AND laeuft_ab > ?').bind(a.id, jetzt).first();
  const genutzt = a.datenraumId && g.online ? await checksGenutzt(db, a.datenraumId, st.id, jetzt) : 0;
  const routen = { genutzt: a.datenraumId && g.online ? await routenGenutzt(db, a.datenraumId, st.id, jetzt) : 0, extra: await routenExtraFrei(db, a.id) };
  const scans = a.datenraumId && g.scans !== 0 ? await lesenGenutzt(db, a.datenraumId, jetzt, st.id) : 0;
  return {
    ok: true,
    stufe: { id: st.id, name: st.name, bis: st.bis },
    grenzen: { geraete: g.geraete, checks: g.checks, routen: g.routen, fahrzeuge: g.fahrzeuge, online: g.online, scans: g.scans },
    nutzung: { geraete: geraete ? geraete.n : 0, checks: genutzt, checksFrei: g.checks === null ? null : Math.max(0, g.checks - genutzt), zeitraumTage: CHECK_ZEITRAUM_TAGE, extra: await extraFrei(db, a.id),
      routen: routen.genutzt, routenFrei: g.routen === null ? null : Math.max(0, g.routen - routen.genutzt), routenExtra: routen.extra,
      scans, scansFrei: g.scans === null ? null : Math.max(0, g.scans - scans), scansMonat: monatVon(jetzt).name },
    rolle: await rolleVon(db, a.email)
  };
}

/* ---------- 13e-5: Rollen-Tabelle (seit 2.0.73) ---------- */

/* Festlegung des Nutzers (13.11.2026): Eine Tabelle mit E-Mail-Adresse, Name und Funktion (Admin oder Entwickler). Daran erkennt die App, wer den Bereich
   „Nur für Entwickler“ sieht (Admin und Entwickler). Ändern dürfen die Tabelle nur Admins. Der erste Admin wird einmal von Hand eingetragen (13e-5.sql). */
export const FUNKTIONEN = ['admin', 'entwickler'];
const MAX_ROLLEN = 50;

/* Die Funktion einer E-Mail-Adresse: 'admin', 'entwickler' oder null. Fehlt die Tabelle noch, gibt es keine Rolle. */
async function rolleVon(db, email) {
  try {
    const z = await db.prepare('SELECT funktion FROM rolle WHERE email = ?').bind(String(email || '').toLowerCase()).first();
    return z && FUNKTIONEN.includes(z.funktion) ? z.funktion : null;
  } catch (e) { if (fehltTabelle(e)) return null; throw e; }
}
async function nurAdmin(request, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  if (await rolleVon(db, a.email) !== 'admin') throw new HttpFehler(403, 'Die Rollen dürfen nur Administratoren ändern.');
  return a;
}
async function rolleListe(request, env, db, jetzt) {
  /* Lesen dürfen Admin und Entwickler (beide sehen alle Kacheln im Bereich), ändern nur Admins. */
  const a = await authentifizieren(request, db, jetzt);
  if (!(await rolleVon(db, a.email))) throw new HttpFehler(403, 'Diese Tabelle sehen nur Administratoren und Entwickler.');
  const r = await db.prepare('SELECT email, name, funktion FROM rolle ORDER BY funktion, email').all();
  return { ok: true, rollen: (r.results || []).map((x) => ({ email: x.email, name: x.name, funktion: x.funktion })) };
}
async function rolleSetzen(request, env, db, jetzt) {
  const a = await nurAdmin(request, db, jetzt);
  const b = await bodyLesen(request);
  const email = emailNormal(b.email);
  const name = typeof b.name === 'string' ? b.name.trim() : '';
  if (!name || name.length > 80) throw new HttpFehler(400, 'Der Name fehlt oder ist zu lang (höchstens 80 Zeichen).', { feld: 'name' });
  if (!FUNKTIONEN.includes(b.funktion)) throw new HttpFehler(400, 'Die Funktion muss Admin oder Entwickler sein.', { feld: 'funktion' });
  const alt = await db.prepare('SELECT funktion FROM rolle WHERE email = ?').bind(email).first();
  if (!alt) {
    const n = await db.prepare('SELECT COUNT(*) AS n FROM rolle').first();
    if (n && n.n >= MAX_ROLLEN) throw new HttpFehler(400, 'Es sind höchstens ' + MAX_ROLLEN + ' Einträge möglich.');
  }
  if (email === a.email && b.funktion !== 'admin') throw new HttpFehler(400, 'Du kannst dich nicht selbst zum Entwickler machen. Das macht ein anderer Admin.', { feld: 'funktion' });
  await db.prepare('INSERT INTO rolle (email, name, funktion) VALUES (?, ?, ?) ON CONFLICT(email) DO UPDATE SET name = excluded.name, funktion = excluded.funktion').bind(email, name, b.funktion).run();
  return { ok: true };
}
async function rolleEntfernen(request, env, db, jetzt) {
  const a = await nurAdmin(request, db, jetzt);
  const b = await bodyLesen(request);
  const email = emailNormal(b.email);
  if (email === a.email) throw new HttpFehler(400, 'Du kannst dich nicht selbst entfernen. Das macht ein anderer Admin.', { feld: 'email' });
  await db.prepare('DELETE FROM rolle WHERE email = ?').bind(email).run();
  return { ok: true };
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
  /* Gast (13f-4): Mit „freigabe“ prüft ein Gast in der Planung oder Nutzung. Der Check zählt zum Kontingent des Besitzers (Festlegung vom 12.11.), der Gast hat keines. */
  let gastF = null, zahler = { id: a.id, datenraumId: a.datenraumId };
  if (b.freigabe !== undefined && b.freigabe !== null && b.freigabe !== '') {
    gastF = await gastFreigabe(db, a, b.freigabe, jetzt);
    const besitzer = await db.prepare('SELECT nutzer_id FROM datenraum WHERE id = ?').bind(gastF.datenraum_id).first();
    if (!besitzer) throw new HttpFehler(404, 'Dieses Fahrzeug wird nicht mehr geteilt.');
    zahler = { id: besitzer.nutzer_id, datenraumId: gastF.datenraum_id };
  }
  if (!zahler.datenraumId) throw new HttpFehler(400, 'Zu diesem Konto gehört noch kein Datenraum.');
  const st = await stufeVon(db, zahler.id, jetzt, false);
  if (!st.grenzen.online) {
    throw new HttpFehler(402, gastF ? 'Online-Checks sind in der Stufe des Besitzers nicht enthalten.' : 'Online-Checks gibt es ab der Stufe Mittel. Deine Stufe ist ' + st.name + '.', gastF ? {} : { stufe: st.id });
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

  if (gastF) await bremsen(db, await schluesselFuer('chk-g', a.id), 8, 10 * MINUTE, jetzt, 'Es wurden zu viele Checks hintereinander gestartet.');
  await bremsen(db, await schluesselFuer('chk', zahler.datenraumId), 8, 10 * MINUTE, jetzt, 'Es wurden zu viele Checks hintereinander gestartet.');
  const genutzt = await checksGenutzt(db, zahler.datenraumId, st.id, jetzt);
  /* Ist das Kontingent der Stufe aufgebraucht, werden nachgekaufte Recherchen benutzt (seit 2.0.72). Sie zählen nicht zum Kontingent (Stufe „extra“). */
  let extraGenommen = false;
  if (st.grenzen.checks !== null && genutzt >= st.grenzen.checks) {
    extraGenommen = await extraNehmen(db, zahler.id);
    if (!extraGenommen) {
      if (gastF) throw new HttpFehler(402, 'Das Kontingent des Besitzers für Online-Checks ist aufgebraucht. Ein gespeicherter Check zählt nicht.', {});
      throw new HttpFehler(402, 'Dein Kontingent ist aufgebraucht: ' + genutzt + ' von ' + st.grenzen.checks + ' Online-Checks in den letzten 12 Monaten. Ein gespeicherter Check zählt nicht. Unter Konto kannst du 5 zusätzliche Recherchen kaufen.', { genutzt, grenze: st.grenzen.checks, stufe: st.id });
    }
  }
  const nid = crypto.randomUUID();
  try {
    await db.prepare('INSERT INTO check_nutzung (id, datenraum_id, art, stufe, am, status) VALUES (?, ?, ?, ?, ?, ?)').bind(nid, zahler.datenraumId, art, extraGenommen ? 'extra' : st.id, jetzt, 'laeuft').run();
  } catch (e) { if (extraGenommen) await extraZurueck(db, zahler.id); throw e; }
  async function zurueck() {
    try { await db.prepare('DELETE FROM check_nutzung WHERE id = ?').bind(nid).run(); } catch (e) { /* wird später aufgeräumt */ }
    if (extraGenommen) await extraZurueck(db, zahler.id);
  }

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
  /* Dem Gast zeigt der Dienst nie die Zahlen des Besitzers. */
  if (gastF) return { ok: true, gespeichert: false, antwort, kontingent: null };
  const kontingent = { genutzt: extraGenommen ? genutzt : genutzt + 1, grenze: st.grenzen.checks, stufe: st.id };
  if (extraGenommen) kontingent.extraFrei = await extraFrei(db, a.id);
  return { ok: true, gespeichert: false, antwort, kontingent };
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
  /* Die Freischalt-Seite des Betreibers ruft den Dienst von seiner eigenen Adresse aus auf: gleicher Ursprung, keine Kopfzeilen nötig. */
  if (ursprung && ursprung !== url.origin) {
    /* Die Ablehnung trägt die Kopfzeile für diese Adresse, damit die App „abgelehnt“ von „keine Verbindung“ unterscheiden kann. Sie enthält nur den Fehlertext. */
    if (!erlaubteUrspruenge(env).includes(ursprung)) return antwort(403, { ok: false, error: 'Diese App-Adresse ist beim Dienst nicht erlaubt.' }, { 'Access-Control-Allow-Origin': ursprung, 'Vary': 'Origin' });
    cors = { 'Access-Control-Allow-Origin': ursprung, 'Vary': 'Origin', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS', 'Access-Control-Expose-Headers': 'X-Verschluesselt', 'Access-Control-Max-Age': '600' };
  }
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors || {} });

  try {
    const weg = request.method + ' ' + url.pathname.replace(/\/+$/, '');
    if (weg === 'GET /gesundheit') return antwort(200, await gesundheit(env), cors);
    /* Anfragen aus der App (cors gesetzt) müssen von einer Version ab der Mindestversion kommen (seit 2.0.101). */
    if (cors) appPruefen(url, env);
    const wege = {
      'POST /konto/registrieren': registrieren,
      'POST /konto/code-anfordern': codeAnfordern,
      'POST /konto/code-pruefen': codePruefen,
      'POST /konto/anmelden': anmelden,
      'GET /konto/ich': ich,
      'POST /konto/passwort-setzen': passwortSetzen,
      'POST /konto/abmelden': abmelden,
      'GET /konto/geraete': geraeteListe,
      'POST /konto/geraet-abmelden': geraetAbmelden,
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
      'POST /geteilt/erfassen': geteiltErfassen,
      'POST /geteilt/kontrolle': geteiltKontrolle,
      'POST /kontrolle/erstellen': kontrolleErstellen,
      'POST /kontrolle/widerrufen': kontrolleWiderrufen,
      'GET /kontrolle/lesen': kontrolleLesen,
      'GET /kontrolle/datei': kontrolleDatei,
      'GET /konto/stufe': kontoStufe,
      'GET /rolle/liste': rolleListe,
      'POST /rolle/setzen': rolleSetzen,
      'POST /rolle/entfernen': rolleEntfernen,
      'POST /check/senden': checkSenden,
      'POST /route/planen': routePlanen,
      'POST /lesen/senden': lesenSenden,
      'POST /bezahlen/starten': bezahlenStarten,
      'POST /gutschein/pruefen': gutscheinPruefen,
      'POST /gutschein/einloesen': gutscheinEinloesen,
      'POST /gutschein/anlegen': gutscheinAnlegen,
      'GET /gutschein/liste': gutscheinListe,
      'POST /gutschein/loeschen': gutscheinLoeschen,
      'GET /bezahlen/paypal/zurueck': paypalZurueck,
      'GET /bezahlen/paypal/abbruch': paypalAbbruch,
      'GET /bezahlen/verlaengern': verlaengernLink,
      'GET /freischalten': freischaltSeite,
      'POST /freischalten/liste': freischaltListe,
      'POST /freischalten/bestaetigen': freischaltBestaetigen,
      'POST /freischalten/direkt': freischaltDirekt,
      'POST /freischalten/loeschen': freischaltLoeschen,
      'GET /verwaltung/statistik': verwaltungStatistik,
      'GET /verwaltung/bestellungen': verwaltungBestellungen,
      'POST /verwaltung/bestaetigen': verwaltungBestaetigen,
      'POST /verwaltung/direkt': verwaltungDirekt,
      'GET /push/schluessel': pushSchluessel,
      'POST /push/anmelden': pushAnmelden,
      'POST /push/abmelden': pushAbmelden,
      'POST /alarm/senden': alarmSenden,
      'POST /verwaltung/loeschen': verwaltungLoeschen
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
    if (e && /no such table/i.test(String(e.message || e))) return antwort(503, { ok: false, error: 'Im Dienst fehlen Tabellen in der Datenbank. Die SQL-Zeilen der Einrichtung (Schritt 13b, 13d, 13c, 13e, 13e-5 und 13g) müssen noch ausgeführt werden.' }, cors);
    return antwort(500, { ok: false, error: 'Im Dienst ist ein Fehler aufgetreten.' }, cors);
  }
}

/* ---------- 13e-4: Bezahlung (seit 2.0.72) ---------- */

/* Festlegung des Nutzers (12.11.2026): nur Jahreszahlung (12 × 4,99 € und 12 × 9,99 €), kein Abo, keine automatische Abbuchung.
   Zusätzliche Online-Recherchen nur in Blöcken zu 5 für 9,99 €. Die Preise stehen nur hier und in js/konto.js (ein Test vergleicht beide).
   Der Dienst speichert nur Stufe und Ablaufdatum, Zahlungsdaten bekommt er nie zu sehen. Für die Buchhaltung gibt es je Zahlung eine Zeile
   in „beleg“ (Nummer, Datum, Adresse, Leistung, Betrag), die auch nach dem Löschen eines Kontos bleibt. */
export const PRODUKTE = {
  mittel: { name: 'MobiMory Mittel, Nutzung für ein Jahr', kurz: 'Mittel (ein Jahr)', cent: 5988, art: 'stufe', stufe: 'mittel' },
  voll: { name: 'MobiMory Voll, Nutzung für ein Jahr', kurz: 'Voll (ein Jahr)', cent: 11988, art: 'stufe', stufe: 'voll' },
  recherche5: { name: '5 zusätzliche Online-Recherchen', kurz: '5 Recherchen', cent: 999, art: 'checks', anzahl: 5 },
  route100: { name: '100 zusätzliche Routen', kurz: '100 Routen', cent: 999, art: 'routen', anzahl: 100 }
};
const ERINNERUNG_TAGE = [30, 7];
const LINK_TAGE = 45;
const PAYPAL_BESTELLUNG_TAGE = 3;
const UEBERWEISUNG_BESTELLUNG_TAGE = 60;
const MAX_OFFENE_UEBERWEISUNGEN = 5;
const DIENST_URL_STANDARD = 'https://konto.mobimory.com';

function dienstUrl(env) {
  const u = env && typeof env.DIENST_URL === 'string' ? env.DIENST_URL.trim().replace(/\/+$/, '') : '';
  return /^https:\/\/[^\s/]+$/.test(u) ? u : DIENST_URL_STANDARD;
}
function appUrl(env) { return erlaubteUrspruenge(env)[0] || ''; }
function datumDe(ms) { const d = new Date(ms); return String(d.getUTCDate()).padStart(2, '0') + '.' + String(d.getUTCMonth() + 1).padStart(2, '0') + '.' + d.getUTCFullYear(); }
function plusJahr(ms) { const d = new Date(ms); d.setUTCFullYear(d.getUTCFullYear() + 1); return d.getTime(); }
function centText(cent) { return euroText(cent / 100); }
function centWert(cent) { return (cent / 100).toFixed(2); }

function produktVon(roh) {
  const id = typeof roh === 'string' ? roh : '';
  if (!Object.prototype.hasOwnProperty.call(PRODUKTE, id)) throw new HttpFehler(400, 'Dieses Angebot gibt es nicht.', { feld: 'produkt' });
  return { id, p: PRODUKTE[id] };
}

function paypalEingerichtet(env) {
  return !!(env && typeof env.PAYPAL_CLIENT_ID === 'string' && env.PAYPAL_CLIENT_ID.length > 5 && typeof env.PAYPAL_SECRET === 'string' && env.PAYPAL_SECRET.length > 5);
}
function paypalBasis(env) { return env && env.PAYPAL_LIVE === '1' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com'; }
function ueberweisungDaten(env) {
  const t = (n) => (env && typeof env[n] === 'string' ? env[n].trim() : '');
  const iban = t('UEBERWEISUNG_IBAN').replace(/\s+/g, '');
  const inhaber = t('UEBERWEISUNG_INHABER');
  if (iban.length < 15 || !inhaber) return null;
  return { inhaber, iban, bic: t('UEBERWEISUNG_BIC') };
}
function adminToken(env) { return env && typeof env.FREISCHALT_TOKEN === 'string' && env.FREISCHALT_TOKEN.length >= 20 ? env.FREISCHALT_TOKEN : ''; }
function belegAnschrift(env) { return env && typeof env.BELEG_ANSCHRIFT === 'string' && env.BELEG_ANSCHRIFT.trim() ? env.BELEG_ANSCHRIFT.trim() : ''; }

async function paypalToken(env, holen) {
  const basic = btoa(env.PAYPAL_CLIENT_ID + ':' + env.PAYPAL_SECRET);
  let r, j = null;
  try {
    r = await holen(paypalBasis(env) + '/v1/oauth2/token', { method: 'POST', headers: { Authorization: 'Basic ' + basic, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=client_credentials' });
    j = await r.json();
  } catch (e) { throw new HttpFehler(502, 'PayPal ist gerade nicht erreichbar. Bitte später noch einmal versuchen.'); }
  if (!r.ok || !j || typeof j.access_token !== 'string') throw new HttpFehler(502, 'PayPal hat die Anmeldung des Dienstes abgelehnt.');
  return j.access_token;
}

/* Was ist erlaubt zu kaufen? Das Entwickler-Konto nie, Mittel nicht bei laufendem Voll, Recherchen nur mit Online-Stufe. */
async function bestellPruefen(db, nutzerId, produktId, jetzt) {
  const st = await stufeVon(db, nutzerId, jetzt, false);
  if (st.id === 'entwickler') throw new HttpFehler(400, 'Dieses Konto hat die Stufe Entwickler und braucht nichts zu kaufen.');
  const p = PRODUKTE[produktId];
  if (p.art === 'stufe' && p.stufe === 'mittel' && st.id === 'voll') throw new HttpFehler(400, 'Du hast bereits Voll' + (st.bis ? ' (bis ' + datumDe(st.bis) + ')' : '') + '. Mittel kannst du nach dem Ablauf kaufen.');
  if (p.art === 'checks' && !st.grenzen.online) throw new HttpFehler(400, 'Zusätzliche Recherchen gibt es ab der Stufe Mittel oder in der Testwoche.');
  if (p.art === 'routen' && !st.grenzen.online) throw new HttpFehler(400, 'Zusätzliche Routen gibt es ab der Stufe Mittel oder in der Testwoche.');
  return st;
}

async function bestellungAnlegen(db, nutzer, produktId, weg, jetzt, gs) {
  const p = PRODUKTE[produktId];
  const id = 'MM-' + zufallCode(8);
  if (gs) {
    /* Mit Gutscheincode (13f-8): bezahlt wird der Preis nach Abzug, der Listenpreis und der Code bleiben an der Bestellung. */
    await gutscheinSchutz(() => db.prepare('INSERT INTO bestellung (id, nutzer_id, email, produkt, cent, weg, paypal_id, erstellt_am, gutschein, liste_cent) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)')
      .bind(id, nutzer.id, nutzer.email, produktId, gs.zahlCent, weg, jetzt, gs.code, p.cent).run());
    return id;
  }
  await db.prepare('INSERT INTO bestellung (id, nutzer_id, email, produkt, cent, weg, paypal_id, erstellt_am) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)').bind(id, nutzer.id, nutzer.email, produktId, p.cent, weg, jetzt).run();
  return id;
}

/* Legt bei PayPal eine Bestellung an und gibt die Adresse zurück, zu der der Kunde zum Bezahlen geht. */
async function paypalBestellen(env, db, nutzer, produktId, jetzt, optionen, gs) {
  if (!paypalEingerichtet(env)) throw new HttpFehler(503, 'Das Bezahlen mit PayPal ist im Dienst noch nicht eingerichtet.');
  await bestellPruefen(db, nutzer.id, produktId, jetzt);
  await bremsen(db, await schluesselFuer('bez', nutzer.id), 10, 60 * MINUTE, jetzt, 'Es wurden zu viele Bestellungen hintereinander angelegt.');
  const holen = (optionen && optionen.fetch) || fetch;
  const token = await paypalToken(env, holen);
  const p = PRODUKTE[produktId];
  const cent = gs ? gs.zahlCent : p.cent;
  const bid = await bestellungAnlegen(db, nutzer, produktId, 'paypal', jetzt, gs);
  async function weg() { try { await db.prepare('DELETE FROM bestellung WHERE id = ?').bind(bid).run(); } catch (e) { /* wird später aufgeräumt */ } }
  let r, j = null;
  try {
    r = await holen(paypalBasis(env) + '/v2/checkout/orders', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', 'PayPal-Request-Id': bid },
      body: JSON.stringify({
        intent: 'CAPTURE',
        purchase_units: [{ reference_id: bid, custom_id: bid, description: p.name, amount: { currency_code: 'EUR', value: centWert(cent) } }],
        payment_source: { paypal: { experience_context: {
          brand_name: 'MobiMory', locale: 'de-DE', landing_page: 'LOGIN', shipping_preference: 'NO_SHIPPING', user_action: 'PAY_NOW',
          payment_method_preference: 'IMMEDIATE_PAYMENT_REQUIRED',
          return_url: dienstUrl(env) + '/bezahlen/paypal/zurueck?b=' + bid,
          cancel_url: dienstUrl(env) + '/bezahlen/paypal/abbruch'
        } } }
      })
    });
    j = await r.json();
  } catch (e) { await weg(); throw new HttpFehler(502, 'PayPal ist gerade nicht erreichbar. Bitte später noch einmal versuchen.'); }
  const link = j && Array.isArray(j.links) ? j.links.find((l) => l && (l.rel === 'payer-action' || l.rel === 'approve')) : null;
  if (!r.ok || !j || typeof j.id !== 'string' || !link || !/^https:\/\//.test(link.href || '')) { await weg(); throw new HttpFehler(502, 'PayPal hat die Bestellung nicht angenommen.'); }
  await db.prepare('UPDATE bestellung SET paypal_id = ? WHERE id = ?').bind(j.id, bid).run();
  return { url: link.href, referenz: bid };
}

/* Verbucht eine bezahlte Bestellung: Beleg, Stufe oder Recherchen, Mail. Ein zweiter Aufruf mit derselben Referenz tut nichts. */
async function bestellungAbschliessen(env, db, best, weg, referenz, jetzt) {
  const alt = await db.prepare('SELECT nummer FROM beleg WHERE referenz = ?').bind(referenz).first();
  if (alt) { await db.prepare('DELETE FROM bestellung WHERE id = ?').bind(best.id).run(); return { nummer: alt.nummer, neu: false, bis: null }; }
  const p = PRODUKTE[best.produkt];
  if (!p) throw new HttpFehler(400, 'Dieses Angebot gibt es nicht.');
  const jahr = new Date(jetzt).getUTCFullYear();
  const z = await db.prepare('INSERT INTO zaehler (schluessel, wert) VALUES (?, 1) ON CONFLICT(schluessel) DO UPDATE SET wert = wert + 1 RETURNING wert').bind('beleg:' + jahr).first();
  const nummer = 'MM-' + jahr + '-' + String(z.wert).padStart(4, '0');
  const gsCode = typeof best.gutschein === 'string' && best.gutschein ? best.gutschein : null;
  let gsProzent = null;
  if (gsCode) { try { const z = await db.prepare('SELECT prozent FROM gutschein WHERE code = ?').bind(gsCode).first(); gsProzent = z ? z.prozent : null; } catch (e) { gsProzent = null; } }
  const liste = [gsCode
    ? db.prepare('INSERT INTO beleg (nummer, am, email, produkt, cent, weg, referenz, gutschein, liste_cent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(nummer, jetzt, best.email, best.produkt, best.cent, weg, referenz, gsCode, best.liste_cent)
    : db.prepare('INSERT INTO beleg (nummer, am, email, produkt, cent, weg, referenz) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(nummer, jetzt, best.email, best.produkt, best.cent, weg, referenz)];
  if (gsCode) {
    /* Zählt die Einlösung, aber nur einmal je Konto (zwei offene Bestellungen mit demselben Code zählen nicht doppelt). */
    liste.push(db.prepare('UPDATE gutschein SET eingeloest = eingeloest + 1 WHERE code = ? AND NOT EXISTS (SELECT 1 FROM gutschein_einloesung WHERE code = ? AND nutzer_id = ?)').bind(gsCode, gsCode, best.nutzer_id));
    liste.push(db.prepare('INSERT OR IGNORE INTO gutschein_einloesung (code, nutzer_id, am, art, referenz) VALUES (?, ?, ?, ?, ?)').bind(gsCode, best.nutzer_id, jetzt, 'rabatt', referenz));
  }
  let bis = null;
  if (p.art === 'stufe') {
    const s = await db.prepare('SELECT stufe, gueltig_bis FROM stufe_konto WHERE nutzer_id = ?').bind(best.nutzer_id).first();
    if (!s || s.stufe !== 'entwickler') {
      const verlaengern = s && s.stufe === p.stufe && s.gueltig_bis !== null && s.gueltig_bis > jetzt;
      bis = plusJahr(verlaengern ? s.gueltig_bis : jetzt);
      liste.push(db.prepare('INSERT OR REPLACE INTO stufe_konto (nutzer_id, stufe, gueltig_bis, geaendert_am) VALUES (?, ?, ?, ?)').bind(best.nutzer_id, p.stufe, bis, jetzt));
    }
  } else if (p.art === 'routen') {
    liste.push(db.prepare('INSERT INTO route_extra (nutzer_id, anzahl) VALUES (?, ?) ON CONFLICT(nutzer_id) DO UPDATE SET anzahl = anzahl + excluded.anzahl').bind(best.nutzer_id, p.anzahl));
  } else {
    liste.push(db.prepare('INSERT INTO check_extra (nutzer_id, anzahl) VALUES (?, ?) ON CONFLICT(nutzer_id) DO UPDATE SET anzahl = anzahl + excluded.anzahl').bind(best.nutzer_id, p.anzahl));
  }
  liste.push(db.prepare('DELETE FROM bestellung WHERE id = ?').bind(best.id));
  await db.batch(liste);
  try { await belegSenden(env, { nummer, am: jetzt, email: best.email, produkt: best.produkt, cent: best.cent, weg, referenz, bis, gutschein: gsCode, listeCent: gsCode ? best.liste_cent : null, prozent: gsProzent }); } catch (e) { console.log('Beleg-Mail nicht gesendet: ' + String(e && e.message || e)); }
  return { nummer, neu: true, bis };
}

/* Der Rabatt steht auf dem Beleg als eigene Zeile (seit 2.0.83): Preis, Rabatt mit Code, dann der gezahlte Betrag. */
function rabattZeilen(b) {
  if (!b.gutschein || !(b.listeCent > b.cent)) return '';
  return '\nPreis: ' + centText(b.listeCent) + '\nRabatt (Code ' + codeAnzeige(b.gutschein) + (b.prozent ? ', ' + prozentText(b.prozent / 100) : '') + '): −' + centText(b.listeCent - b.cent);
}

function belegText(b) {
  const p = PRODUKTE[b.produkt];
  const z = [];
  z.push('Beleg (Rechnung) Nr. ' + b.nummer + '\nDatum: ' + datumDe(b.am));
  z.push('Leistender:\n' + (belegAnschrift(b.env) || 'Ralph Hasslacher, 74372 Sersheim'));
  z.push('Empfänger: ' + b.email);
  z.push('Leistung: ' + p.name + (p.art === 'stufe' && b.bis ? ' (Zeitraum ' + datumDe(b.am) + ' bis ' + datumDe(b.bis) + ')' : ' (Leistungszeitpunkt ' + datumDe(b.am) + ')') + rabattZeilen(b) + '\nBetrag: ' + centText(b.cent) + '\nBezahlt per ' + (b.weg === 'paypal' ? 'PayPal' : 'Überweisung') + ', Zahlungsreferenz ' + b.referenz);
  z.push('Gemäß § 19 UStG wird keine Umsatzsteuer berechnet.');
  if (p.art === 'stufe') z.push('Deine Stufe ' + p.stufe.charAt(0).toUpperCase() + p.stufe.slice(1) + (b.bis ? ' gilt jetzt bis ' + datumDe(b.bis) : ' ist freigeschaltet') + '. Es ist kein Abo: Es wird nichts automatisch abgebucht. Vor dem Ablauf bekommst du eine Erinnerung.');
  else if (p.art === 'routen') z.push('Die ' + p.anzahl + ' Routen sind deinem Konto gutgeschrieben. Sie werden benutzt, wenn dein Kontingent an Routen aufgebraucht ist.');
  else z.push('Die ' + p.anzahl + ' Recherchen sind deinem Konto gutgeschrieben. Sie werden benutzt, wenn dein Kontingent aufgebraucht ist.');
  z.push('Bitte hebe diese Mail als Beleg auf.');
  return z.join('\n\n');
}

async function belegSenden(env, b) {
  const text = belegText(Object.assign({ env }, b));
  await mailSenden(env, b.email, 'Dein Beleg Nr. ' + b.nummer + ' – MobiMory', text);
  const kopie = env && typeof env.BELEG_KOPIE === 'string' ? env.BELEG_KOPIE.trim() : '';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(kopie)) { try { await mailSenden(env, kopie, 'Kopie Beleg ' + b.nummer, text); } catch (e) { /* die Kopie ist nur eine Hilfe */ } }
}

/* ---------- 13f-8: Gutscheincodes beim Bezahlen (seit 2.0.83) ---------- */

/* Festlegung des Nutzers (15.11.2026):
   - Der Code gilt bei PayPal und bei Überweisung.
   - Rabatt: mehr als 0 bis 25 % stufenlos, oder genau 100 %. Alles dazwischen lehnt der Dienst ab (PayPal-Festgebühr).
   - 1 bis 25 %: nur für Neukunden beim ersten Kauf (Konto hat nie bezahlt und nie Mittel oder Voll gehabt). Kein Rabatt bei Recherchen und beim Wechsel von Mittel auf Voll.
     Ein Code für viele (mit Obergrenze) oder persönlich (Grenze 1).
   - 100 %: nur persönlich (Grenze 1), auch für Bestandskunden (Geschenk). Gilt für Mittel oder Voll für 1 bis 12 Monate, ohne Zahlung, PayPal wird nicht aufgerufen.
     Gleiche Stufe: die Laufzeit wird angehängt. Höhere Stufe schon da: Dienst lehnt ab. Mittel da und Code gibt Voll: Voll gilt ab sofort, der Rest von Mittel wird nicht angerechnet.
   - Jeder Code hat ein Ablaufdatum. Nur Admins legen Codes an. */
export const GUTSCHEIN_MAX_PROZENT = 25;
const GUTSCHEIN_RANG = { mittel: 1, voll: 2 };
const GUTSCHEIN_MAX_GRENZE = 100000;
const GUTSCHEIN_MAX_ANZAHL = 1000;
const GUTSCHEIN_MAX_JAHRE = 5;

/* Zeigt ein 8-stelliger Code in zwei Vierergruppen (ABCD-EFGH), andere Codes unverändert. */
function codeAnzeige(code) { const c = String(code || ''); return /^[A-Z0-9]{8}$/.test(c) ? c.slice(0, 4) + '-' + c.slice(4) : c; }
/* Eingabe: Groß, ohne Leerzeichen und Striche. Leer, wenn ungültig. */
function gutscheinCode(roh) {
  const t = typeof roh === 'string' ? roh.toUpperCase().replace(/[\s-]+/g, '') : '';
  return /^[A-Z0-9]{4,24}$/.test(t) ? t : '';
}
function plusMonateMs(ms, n) {
  const d = new Date(ms), tag = d.getUTCDate();
  d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() + n);
  const max = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
  d.setUTCDate(Math.min(tag, max));
  return d.getTime();
}

/* Fehlen die Tabellen oder Spalten aus 13f-8.sql, sagt der Dienst es klar. Ohne Code läuft das Bezahlen wie bisher. */
async function gutscheinSchutz(f) {
  try { return await f(); } catch (e) {
    if (e instanceof HttpFehler) throw e;
    if (/no such (table|column)/i.test(String(e && e.message || e))) throw new HttpFehler(503, 'Gutscheincodes gehen noch nicht: Im Dienst fehlen die SQL-Zeilen aus 13f-8.sql. Bitte beim Betreiber melden.');
    throw e;
  }
}

/* Wie viele Versuche pro Stunde: je Konto 20 und je Adresse 60 (Schutz gegen Durchprobieren). */
async function gutscheinBremse(request, db, a, jetzt) {
  await bremsen(db, await schluesselFuer('gs-k', a.id), 20, 60 * MINUTE, jetzt, 'Es wurden zu viele Codes ausprobiert.');
  await bremsen(db, await schluesselFuer('gs-i', request.headers.get('CF-Connecting-IP') || 'unbekannt'), 60, 60 * MINUTE, jetzt, 'Von hier wurden zu viele Codes ausprobiert.');
}

/* Lädt den Code und prüft, ob er für dieses Konto noch zu haben ist. */
async function gutscheinLaden(db, a, roh, jetzt) {
  const code = gutscheinCode(roh);
  if (!code) throw new HttpFehler(400, 'Bitte einen Code eintragen (Buchstaben und Ziffern).', { feld: 'code' });
  const g = await db.prepare('SELECT code, prozent, stufe, monate, grenze, eingeloest, laeuft_ab FROM gutschein WHERE code = ?').bind(code).first();
  if (!g) throw new HttpFehler(400, 'Diesen Code gibt es nicht.', { feld: 'code' });
  if (g.laeuft_ab <= jetzt) throw new HttpFehler(400, 'Dieser Code ist abgelaufen.', { feld: 'code' });
  if (g.eingeloest >= g.grenze) throw new HttpFehler(400, 'Dieser Code ist schon aufgebraucht.', { feld: 'code' });
  const schon = await db.prepare('SELECT 1 AS x FROM gutschein_einloesung WHERE code = ? AND nutzer_id = ?').bind(code, a.id).first();
  if (schon) throw new HttpFehler(400, 'Du hast diesen Code schon eingelöst.', { feld: 'code' });
  return g;
}

/* Neukunde: das Konto hat nie bezahlt (kein Beleg zur E-Mail-Adresse, auch nach einer Kontolöschung) und nie Mittel oder Voll gehabt. */
async function istNeukunde(db, a) {
  const b = await db.prepare('SELECT 1 AS x FROM beleg WHERE lower(email) = ? LIMIT 1').bind(String(a.email || '').toLowerCase()).first();
  if (b) return false;
  const s = await db.prepare("SELECT 1 AS x FROM stufe_konto WHERE nutzer_id = ? AND stufe IN ('mittel', 'voll', 'entwickler')").bind(a.id).first();
  return !s;
}

/* Rabattcode (1 bis 25 %) für ein Angebot: rechnet den Preis. Wirft, wenn der Code hier nicht gilt. */
async function gutscheinRabatt(db, a, g, produktId) {
  const p = PRODUKTE[produktId];
  if (p.art !== 'stufe') throw new HttpFehler(400, 'Der Rabattcode gilt nicht für zusätzliche Recherchen und Routen, nur für den ersten Kauf von Mittel oder Voll.', { feld: 'code' });
  if (!(await istNeukunde(db, a))) throw new HttpFehler(400, 'Dieser Rabattcode gilt nur für Neukunden beim ersten Kauf. Beim Verlängern, beim Wechsel von Mittel auf Voll und bei Recherchen gibt es keinen Rabatt.', { feld: 'code' });
  const rabattCent = Math.round(p.cent * g.prozent / 100);
  return { code: g.code, prozent: g.prozent, listeCent: p.cent, rabattCent, zahlCent: p.cent - rabattCent };
}
function gutscheinAntwort(gs) {
  return { code: codeAnzeige(gs.code), prozent: gs.prozent, preis: centText(gs.listeCent), rabatt: '−' + centText(gs.rabattCent), betrag: centText(gs.zahlCent), cent: gs.zahlCent };
}

/* Beim Bezahlen: gibt die Rechnung des Rabatts zurück. Ein 100-%-Code gehört nicht hierher, er schaltet direkt frei. */
async function gutscheinFuerKauf(db, a, produktId, roh, jetzt) {
  return gutscheinSchutz(async () => {
    const g = await gutscheinLaden(db, a, roh, jetzt);
    if (g.prozent === 100) throw new HttpFehler(400, 'Dieser Code schaltet ohne Bezahlen frei. Bitte „Code einlösen“ wählen.', { feld: 'code' });
    return gutscheinRabatt(db, a, g, produktId);
  });
}

/* Was würde ein 100-%-Code tun? Gibt Stufe und neues Ende zurück oder wirft. Ändert nichts. */
async function gutscheinFreiPlan(db, a, g, jetzt) {
  const st = await stufeVon(db, a.id, jetzt, false);
  if (st.id === 'entwickler') throw new HttpFehler(400, 'Dieses Konto hat die Stufe Entwickler und braucht keinen Code.', { feld: 'code' });
  const rc = GUTSCHEIN_RANG[g.stufe];
  if (!rc || !(g.monate >= 1 && g.monate <= 12)) throw new HttpFehler(400, 'Dieser Code ist nicht in Ordnung. Bitte beim Betreiber melden.', { feld: 'code' });
  const rs = GUTSCHEIN_RANG[st.id] || 0;
  if (rs > rc) throw new HttpFehler(400, 'Du hast bereits ' + st.name + (st.bis ? ' (bis ' + datumDe(st.bis) + ')' : '') + '. Dieser Code gibt nur ' + STUFEN[g.stufe].name + ' und wäre nicht nützlich.', { feld: 'code' });
  let start = jetzt;
  if (rs === rc) {
    if (st.bis === null || st.bis === undefined) throw new HttpFehler(400, 'Deine Stufe ' + st.name + ' hat kein Ablaufdatum, der Code wird nicht gebraucht.', { feld: 'code' });
    start = st.bis;
  }
  return { stufe: g.stufe, name: STUFEN[g.stufe].name, monate: g.monate, bis: plusMonateMs(start, g.monate), verlaengert: rs === rc, ersetzt: rs > 0 && rs < rc ? st.name : null };
}

/* App: Code prüfen, bevor bezahlt wird. Rabattcode: Preise der beiden Stufen. 100-%-Code: Stufe, Laufzeit und neues Ende. */
async function gutscheinPruefen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request, MAX_BODY);
  await gutscheinBremse(request, db, a, jetzt);
  return gutscheinSchutz(async () => {
    const g = await gutscheinLaden(db, a, b.code, jetzt);
    if (g.prozent === 100) {
      const plan = await gutscheinFreiPlan(db, a, g, jetzt);
      return { ok: true, art: 'frei', code: codeAnzeige(g.code), stufe: plan.stufe, stufeName: plan.name, monate: plan.monate, bis: datumDe(plan.bis), verlaengert: plan.verlaengert, ersetzt: plan.ersetzt };
    }
    const preise = {};
    for (const id of ['mittel', 'voll']) {
      const bp = await bestellPruefen(db, a.id, id, jetzt).then(() => true, () => false);
      /* Auch ein Angebot, das gerade nicht kaufbar ist (Mittel bei laufendem Voll), bekommt keinen Preis. */
      if (!bp) continue;
      preise[id] = gutscheinAntwort(await gutscheinRabatt(db, a, g, id));
    }
    return { ok: true, art: 'rabatt', code: codeAnzeige(g.code), prozent: g.prozent, preise };
  });
}

/* 100-%-Code einlösen: Stufe ohne Zahlung setzen. */
async function gutscheinEinloesen(request, env, db, jetzt) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request, MAX_BODY);
  await gutscheinBremse(request, db, a, jetzt);
  return gutscheinSchutz(async () => {
    const g = await gutscheinLaden(db, a, b.code, jetzt);
    if (g.prozent !== 100) throw new HttpFehler(400, 'Das ist ein Rabattcode. Gib ihn beim Bezahlen ein, er schaltet nicht allein frei.', { feld: 'code' });
    const plan = await gutscheinFreiPlan(db, a, g, jetzt);
    /* Erst die Einlösung sichern (nur wenn noch frei und nicht abgelaufen), dann Stufe setzen. */
    const r = await db.prepare('UPDATE gutschein SET eingeloest = eingeloest + 1 WHERE code = ? AND eingeloest < grenze AND laeuft_ab > ?').bind(g.code, jetzt).run();
    if (!(r && r.meta && r.meta.changes === 1)) throw new HttpFehler(400, 'Dieser Code ist schon aufgebraucht.', { feld: 'code' });
    try {
      await db.batch([
        db.prepare('INSERT OR REPLACE INTO stufe_konto (nutzer_id, stufe, gueltig_bis, geaendert_am) VALUES (?, ?, ?, ?)').bind(a.id, plan.stufe, plan.bis, jetzt),
        db.prepare('INSERT INTO gutschein_einloesung (code, nutzer_id, am, art, referenz) VALUES (?, ?, ?, ?, ?)').bind(g.code, a.id, jetzt, 'frei', plan.stufe + ':' + plan.monate)
      ]);
    } catch (e) {
      try { await db.prepare('UPDATE gutschein SET eingeloest = eingeloest - 1 WHERE code = ? AND eingeloest > 0').bind(g.code).run(); } catch (e2) { /* Support */ }
      throw e;
    }
    const text = 'Hallo,\n\ndein Code ' + codeAnzeige(g.code) + ' ist eingelöst. Dein MobiMory ' + plan.name + ' gilt jetzt bis ' + datumDe(plan.bis) + '.\n\n'
      + (plan.ersetzt ? 'Die restliche Zeit deiner Stufe ' + plan.ersetzt + ' wird nicht angerechnet, ' + plan.name + ' gilt ab sofort.\n\n' : '')
      + 'Es ist kein Abo: Es wird nichts abgebucht. Vor dem Ablauf bekommst du eine Erinnerung. Es wurde nichts bezahlt, deshalb gibt es keinen Beleg.';
    try { await mailSenden(env, a.email, 'MobiMory: Dein Code ist eingelöst', text); } catch (e) { /* die Mail ist nur eine Hilfe */ }
    return { ok: true, art: 'frei', stufe: plan.stufe, stufeName: plan.name, bis: plan.bis, bisText: datumDe(plan.bis) };
  });
}

/* ---- nur Admins: anlegen, auflisten, löschen ---- */

async function gutscheinAnlegen(request, env, db, jetzt) {
  const a = await nurAdmin(request, db, jetzt);
  const b = await bodyLesen(request, MAX_BODY);
  const proz = Number(String(b.prozent === undefined || b.prozent === null ? '' : b.prozent).trim().replace(',', '.'));
  const prozent = Math.round(proz * 100) / 100;
  if (!Number.isFinite(proz) || String(b.prozent).trim() === '' || !((prozent > 0 && prozent <= GUTSCHEIN_MAX_PROZENT) || prozent === 100)) {
    throw new HttpFehler(400, 'Der Rabatt muss mehr als 0 und höchstens ' + GUTSCHEIN_MAX_PROZENT + ' % sein, oder genau 100 %. Dazwischen geht nicht.', { feld: 'prozent' });
  }
  const frei = prozent === 100;
  let stufe = null, monate = null, grenze = 1;
  if (frei) {
    if (!Object.prototype.hasOwnProperty.call(GUTSCHEIN_RANG, b.stufe)) throw new HttpFehler(400, 'Bei 100 % muss die Stufe Mittel oder Voll gewählt sein.', { feld: 'stufe' });
    stufe = b.stufe;
    monate = Number(b.monate);
    if (!Number.isInteger(monate) || monate < 1 || monate > 12) throw new HttpFehler(400, 'Die Laufzeit muss 1 bis 12 Monate sein.', { feld: 'monate' });
  } else {
    grenze = b.grenze === undefined || b.grenze === null || String(b.grenze).trim() === '' ? 1 : Number(b.grenze);
    if (!Number.isInteger(grenze) || grenze < 1 || grenze > GUTSCHEIN_MAX_GRENZE) throw new HttpFehler(400, 'Die Obergrenze der Einlösungen muss eine ganze Zahl von 1 bis ' + GUTSCHEIN_MAX_GRENZE + ' sein.', { feld: 'grenze' });
  }
  const tag = datumTeile(b.laeuftAb);
  if (!tag) throw new HttpFehler(400, 'Das Ablaufdatum fehlt oder ist ungültig (Jahr-Monat-Tag).', { feld: 'laeuftAb' });
  const ablauf = tagEnde(b.laeuftAb);
  if (ablauf <= jetzt) throw new HttpFehler(400, 'Das Ablaufdatum muss in der Zukunft liegen.', { feld: 'laeuftAb' });
  if (ablauf > jetzt + GUTSCHEIN_MAX_JAHRE * 366 * TAG) throw new HttpFehler(400, 'Das Ablaufdatum darf höchstens ' + GUTSCHEIN_MAX_JAHRE + ' Jahre entfernt sein.', { feld: 'laeuftAb' });
  const notiz = typeof b.notiz === 'string' ? b.notiz.trim().slice(0, 80) : '';
  /* Empfänger der Mail (freiwillig, 13f-9): wird nur zum Senden gebraucht und nicht gespeichert. */
  let empfaenger = '';
  if (typeof b.empfaenger === 'string' && b.empfaenger.trim()) {
    try { empfaenger = emailNormal(b.empfaenger); } catch (e) { throw new HttpFehler(400, 'Die E-Mail-Adresse des Empfängers ist ungültig.', { feld: 'empfaenger' }); }
  }
  /* Ein 100-%-Code ist Geld wert: Er wird immer zufällig erzeugt, nie frei gewählt. */
  const eigener = !frei && typeof b.code === 'string' && b.code.trim() ? gutscheinCode(b.code) : '';
  if (!frei && typeof b.code === 'string' && b.code.trim() && !eigener) throw new HttpFehler(400, 'Der Code darf nur Buchstaben und Ziffern enthalten (4 bis 24 Zeichen).', { feld: 'code' });
  return gutscheinSchutz(async () => {
    const n = await db.prepare('SELECT COUNT(*) AS n FROM gutschein').first();
    if (n && n.n >= GUTSCHEIN_MAX_ANZAHL) throw new HttpFehler(400, 'Es sind höchstens ' + GUTSCHEIN_MAX_ANZAHL + ' Codes möglich. Bitte alte löschen.');
    let code = eigener;
    if (eigener) {
      const da = await db.prepare('SELECT 1 AS x FROM gutschein WHERE code = ?').bind(eigener).first();
      if (da) throw new HttpFehler(400, 'Diesen Code gibt es schon.', { feld: 'code' });
    } else {
      for (let i = 0; i < 5 && !code; i++) {
        const c = zufallCode(8);
        const da = await db.prepare('SELECT 1 AS x FROM gutschein WHERE code = ?').bind(c).first();
        if (!da) code = c;
      }
      if (!code) throw new HttpFehler(500, 'Es konnte kein freier Code erzeugt werden. Bitte noch einmal versuchen.');
    }
    await db.prepare('INSERT INTO gutschein (code, prozent, stufe, monate, grenze, eingeloest, laeuft_ab, erstellt_am, erstellt_von, notiz) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)')
      .bind(code, prozent, stufe, monate, grenze, ablauf, jetzt, a.email, notiz || null).run();
    const antwort = { ok: true, code: codeAnzeige(code) };
    if (empfaenger) {
      let r = null;
      try { r = await mailSenden(env, empfaenger, gutscheinMailBetreff(grenze), gutscheinMailText({ code, prozent, stufe, monate, grenze, ablauf })); } catch (e) { r = null; }
      antwort.mail = !!(r && r.gesendet === true);
    }
    return antwort;
  });
}

/* Mail beim Anlegen (13f-9). Persönlicher Code (Grenze 1): an die Person, die ihn einlöst. Code für viele: an den, der ihn verteilt. */
function gutscheinMailBetreff(grenze) { return grenze > 1 ? 'MobiMory: Gutscheincode zum Weitergeben' : 'MobiMory: Dein Gutscheincode'; }
function gutscheinMailText(g) {
  const frei = g.prozent === 100;
  const was = frei
    ? STUFEN[g.stufe].name + ' für ' + g.monate + (g.monate === 1 ? ' Monat' : ' Monate') + ', ohne Bezahlen'
    : String(Math.round(g.prozent * 100) / 100).replace('.', ',') + ' % Rabatt auf den ersten Kauf von Mittel oder Voll (nur für Neukunden)';
  const viele = g.grenze > 1;
  return 'Hallo,\n\n'
    + (viele ? 'hier ist ein MobiMory-Code zum Weitergeben:' : 'für dich gibt es einen MobiMory-Code:') + '\n\n'
    + codeAnzeige(g.code) + '\n\n'
    + 'Das bewirkt er: ' + was + '.\n'
    + 'Er gilt bis ' + datumDe(g.ablauf) + (viele ? ' und kann ' + g.grenze + '-mal eingelöst werden (je Konto einmal).' : ' und kann einmal eingelöst werden.') + '\n\n'
    + (viele ? 'So lösen ihn die Empfänger ein: ' : 'So löst du ihn ein: ')
    + 'In der App unter Konto › Deine Stufe › Gutscheincode bei dem Angebot eintragen, das gewünscht ist (Mittel oder Voll), „Code prüfen“ antippen und dann ' + (frei ? '„Code einlösen“.' : 'wie gewohnt bezahlen. Der Preis steht dann mit Rabatt da.') + '\n\n'
    + 'Bitte gib den Code nur weiter, wenn das so gedacht ist.';
}

async function gutscheinListe(request, env, db, jetzt) {
  await nurAdmin(request, db, jetzt);
  return gutscheinSchutz(async () => {
    const r = await db.prepare('SELECT code, prozent, stufe, monate, grenze, eingeloest, laeuft_ab, erstellt_am, notiz FROM gutschein ORDER BY erstellt_am DESC, code LIMIT 300').all();
    return { ok: true, codes: (r.results || []).map((x) => ({ code: codeAnzeige(x.code), prozent: x.prozent, stufe: x.stufe || null, monate: x.monate === undefined ? null : x.monate, grenze: x.grenze, eingeloest: x.eingeloest,
      laeuftAb: datumText(x.laeuft_ab), abgelaufen: x.laeuft_ab <= jetzt, aufgebraucht: x.eingeloest >= x.grenze, notiz: x.notiz || '' })) };
  });
}

async function gutscheinLoeschen(request, env, db, jetzt) {
  await nurAdmin(request, db, jetzt);
  const b = await bodyLesen(request, MAX_BODY);
  const code = gutscheinCode(b.code);
  if (!code) throw new HttpFehler(400, 'Der Code fehlt.', { feld: 'code' });
  return gutscheinSchutz(async () => {
    await db.prepare('DELETE FROM gutschein WHERE code = ?').bind(code).run();
    return { ok: true };
  });
}

/* ---------- die Wege ---------- */

const SEITE_KOPF = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'" };
function kleineSeite(titel, text, status, link) {
  const a = link && /^https:\/\//.test(link.url) ? '<p><a href="' + htmlSauber(link.url).replace(/"/g, '&quot;') + '">' + htmlSauber(link.text) + '</a></p>' : '';
  const html = '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' + htmlSauber(titel) + '</title>'
    + '<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem;line-height:1.5}a{font-size:1.2rem}</style></head><body><h1>' + htmlSauber(titel) + '</h1><p>' + htmlSauber(text) + '</p>' + a + '</body></html>';
  return new Response(html, { status: status || 200, headers: SEITE_KOPF });
}

/* App: Bezahlen starten. weg = „paypal“ (Antwort mit Adresse) oder „ueberweisung“ (Antwort mit Bankdaten und Verwendungszweck). */
async function bezahlenStarten(request, env, db, jetzt, optionen) {
  const a = await authentifizieren(request, db, jetzt);
  const b = await bodyLesen(request, MAX_BODY);
  const { id, p } = produktVon(b.produkt);
  const weg = b.weg === 'ueberweisung' ? 'ueberweisung' : (b.weg === 'paypal' ? 'paypal' : '');
  if (!weg) throw new HttpFehler(400, 'Der Zahlungsweg fehlt oder ist unbekannt.', { feld: 'weg' });
  /* Gutscheincode (13f-8): nur ein Rabattcode (1 bis 25 %) gilt beim Bezahlen. Ohne Code läuft alles wie bisher. */
  const codeRoh = typeof b.code === 'string' ? b.code.trim() : '';
  const gs = codeRoh ? await gutscheinFuerKauf(db, a, id, codeRoh, jetzt) : null;
  const preis = gs ? gs.zahlCent : p.cent;
  if (weg === 'paypal') {
    const r = await paypalBestellen(env, db, { id: a.id, email: a.email }, id, jetzt, optionen, gs);
    return Object.assign({ ok: true, weg, produkt: id, betrag: centText(preis), url: r.url }, gs ? { rabatt: gutscheinAntwort(gs) } : {});
  }
  const bank = ueberweisungDaten(env);
  if (!bank) throw new HttpFehler(503, 'Die Überweisung ist im Dienst noch nicht eingerichtet.');
  await bestellPruefen(db, a.id, id, jetzt);
  await bremsen(db, await schluesselFuer('bez', a.id), 10, 60 * MINUTE, jetzt, 'Es wurden zu viele Bestellungen hintereinander angelegt.');
  const offen = await db.prepare("SELECT COUNT(*) AS n FROM bestellung WHERE nutzer_id = ? AND weg = 'ueberweisung'").bind(a.id).first();
  if (offen && offen.n >= MAX_OFFENE_UEBERWEISUNGEN) throw new HttpFehler(400, 'Es warten schon ' + MAX_OFFENE_UEBERWEISUNGEN + ' Überweisungen auf Geldeingang. Bitte warte, bis sie verbucht sind.');
  const ref = await bestellungAnlegen(db, { id: a.id, email: a.email }, id, 'ueberweisung', jetzt, gs);
  const text = 'Du hast ' + p.name + ' für ' + centText(preis) + ' bestellt' + (gs ? ' (Preis ' + centText(p.cent) + ', Rabatt mit Code ' + codeAnzeige(gs.code) + ': −' + centText(gs.rabattCent) + ')' : '') + '. Bitte überweise den Betrag:\n\n'
    + 'Empfänger: ' + bank.inhaber + '\nIBAN: ' + bank.iban + (bank.bic ? '\nBIC: ' + bank.bic : '') + '\nBetrag: ' + centText(preis) + '\nVerwendungszweck: ' + ref
    + '\n\nBitte genau diesen Verwendungszweck angeben, damit die Zahlung zugeordnet wird. Nach Geldeingang wird dein Konto freigeschaltet, du bekommst dann eine Mail mit dem Beleg. Es ist kein Abo, es wird nichts abgebucht.';
  let mail = false;
  try { await mailSenden(env, a.email, 'Deine Überweisung an MobiMory (' + ref + ')', text); mail = true; } catch (e) { mail = false; }
  return Object.assign({ ok: true, weg, produkt: id, betrag: centText(preis), referenz: ref, empfaenger: bank.inhaber, iban: bank.iban, bic: bank.bic, verwendungszweck: ref, mail }, gs ? { rabatt: gutscheinAntwort(gs) } : {});
}

/* PayPal schickt den Kunden nach dem Bezahlen hierher zurück: Die Zahlung wird abgeschlossen (capture) und die Stufe gesetzt. */
async function paypalZurueck(request, env, db, jetzt, optionen) {
  const bid = (new URL(request.url).searchParams.get('b') || '').toUpperCase();
  const app = appUrl(env) ? { url: appUrl(env), text: 'Zurück zur App' } : null;
  if (!/^MM-[A-Z0-9]{8}$/.test(bid)) return kleineSeite('Unbekannte Bestellung', 'Diese Adresse gehört zu keiner Bestellung.', 404, app);
  const best = await db.prepare("SELECT * FROM bestellung WHERE id = ? AND weg = 'paypal'").bind(bid).first();
  if (!best || !best.paypal_id) return kleineSeite('Schon verbucht', 'Diese Zahlung ist schon verbucht oder die Bestellung gibt es nicht mehr. Öffne die App: Unter Konto siehst du deine Stufe.', 200, app);
  const holen = (optionen && optionen.fetch) || fetch;
  const token = await paypalToken(env, holen);
  const kopf = { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' };
  let order = null;
  try {
    const r = await holen(paypalBasis(env) + '/v2/checkout/orders/' + encodeURIComponent(best.paypal_id) + '/capture', { method: 'POST', headers: Object.assign({ 'PayPal-Request-Id': best.id + '-capture' }, kopf), body: '{}' });
    let j = null;
    try { j = await r.json(); } catch (e) { j = null; }
    if (r.ok) order = j;
    else if (/ORDER_ALREADY_CAPTURED/.test(JSON.stringify(j || {}))) {
      const g = await holen(paypalBasis(env) + '/v2/checkout/orders/' + encodeURIComponent(best.paypal_id), { method: 'GET', headers: kopf });
      order = g.ok ? await g.json() : null;
    }
  } catch (e) { order = null; }
  const pu = order && Array.isArray(order.purchase_units) ? order.purchase_units[0] : null;
  const cap = pu && pu.payments && Array.isArray(pu.payments.captures) ? pu.payments.captures[0] : null;
  if (!order || order.status !== 'COMPLETED' || !cap || cap.status !== 'COMPLETED' || typeof cap.id !== 'string') {
    return kleineSeite('Zahlung nicht abgeschlossen', 'Die Zahlung ist bei PayPal nicht abgeschlossen worden. Es wurde nichts abgebucht oder sie ist noch in Prüfung. Du kannst es in der App noch einmal versuchen.', 200, app);
  }
  if (!cap.amount || cap.amount.currency_code !== 'EUR' || cap.amount.value !== centWert(best.cent)) {
    console.log('Bezahlung: Betrag passt nicht, Bestellung ' + best.id);
    return kleineSeite('Betrag stimmt nicht', 'Der bezahlte Betrag passt nicht zur Bestellung. Das Konto wurde nicht freigeschaltet. Bitte melde dich beim Betreiber (info@mobimory.com) und nenne die Bestellnummer ' + best.id + '.', 200, app);
  }
  const erg = await bestellungAbschliessen(env, db, best, 'paypal', cap.id, jetzt);
  return kleineSeite('Danke, die Zahlung ist angekommen', 'Dein Konto ist freigeschaltet' + (erg.bis ? ' bis ' + datumDe(erg.bis) : '') + '. Der Beleg ' + erg.nummer + ' kommt per E-Mail. Öffne die App, unter Konto siehst du die neue Stufe.', 200, app);
}

async function paypalAbbruch(request, env) {
  const app = appUrl(env) ? { url: appUrl(env), text: 'Zurück zur App' } : null;
  return kleineSeite('Bezahlen abgebrochen', 'Du hast das Bezahlen abgebrochen. Es wurde nichts abgebucht.', 200, app);
}

/* Link aus der Erinnerungsmail: gehört zu einem Konto und einem Angebot, gilt 45 Tage, legt die PayPal-Bestellung an und leitet weiter. */
async function linkToken(env, nutzerId, produktId, bis) {
  const teil = zuBase64Url(kodieren.encode(nutzerId + '|' + produktId + '|' + bis));
  return teil + '.' + zuHex(await hmac(pepper(env), 'zahllink:' + teil));
}
async function verlaengernLink(request, env, db, jetzt, optionen) {
  const t = new URL(request.url).searchParams.get('t') || '';
  const m = /^([A-Za-z0-9_-]{10,300})\.([0-9a-f]{64})$/.exec(t);
  const app = appUrl(env) ? { url: appUrl(env), text: 'Zur App' } : null;
  if (!m) return kleineSeite('Link ungültig', 'Dieser Link ist ungültig. Öffne die App, dort kannst du unter Konto bezahlen.', 400, app);
  const soll = await hmac(pepper(env), 'zahllink:' + m[1]);
  const ist = new Uint8Array(m[2].match(/../g).map((x) => parseInt(x, 16)));
  if (!gleich(soll, ist)) return kleineSeite('Link ungültig', 'Dieser Link ist ungültig. Öffne die App, dort kannst du unter Konto bezahlen.', 400, app);
  const teile = new TextDecoder().decode(ausBase64Url(m[1])).split('|');
  const bis = Number(teile[2]);
  if (teile.length !== 3 || !Number.isFinite(bis) || bis < jetzt) return kleineSeite('Link abgelaufen', 'Dieser Link gilt nicht mehr. Öffne die App, dort kannst du unter Konto bezahlen.', 400, app);
  const n = await db.prepare('SELECT id, email FROM nutzer WHERE id = ?').bind(teile[0]).first();
  if (!n || !Object.prototype.hasOwnProperty.call(PRODUKTE, teile[1])) return kleineSeite('Link ungültig', 'Dieser Link gehört zu keinem Konto mehr.', 400, app);
  try {
    const r = await paypalBestellen(env, db, n, teile[1], jetzt, optionen);
    return new Response(null, { status: 302, headers: { Location: r.url, 'Cache-Control': 'no-store' } });
  } catch (e) {
    if (e instanceof HttpFehler) return kleineSeite('Bezahlen gerade nicht möglich', e.message, 200, app);
    throw e;
  }
}

/* Erinnerung vor dem Ablauf: je Konto und Ablaufdatum eine Mail bei 30 und eine bei 7 Tagen (nie beide auf einmal). Läuft im Cron-Auslöser mit. */
export async function erinnerungenSenden(env, db, jetzt) {
  const ergebnis = { gesendet: 0, fehler: 0 };
  let zeilen;
  try {
    zeilen = await db.prepare("SELECT s.nutzer_id AS nutzer_id, s.stufe AS stufe, s.gueltig_bis AS bis, n.email AS email FROM stufe_konto s JOIN nutzer n ON n.id = s.nutzer_id WHERE s.stufe IN ('mittel', 'voll') AND s.gueltig_bis IS NOT NULL AND s.gueltig_bis > ? AND s.gueltig_bis <= ? ORDER BY s.gueltig_bis LIMIT 50")
      .bind(jetzt, jetzt + ERINNERUNG_TAGE[0] * TAG).all();
  } catch (e) { if (fehltTabelle(e)) return ergebnis; throw e; }
  for (const z of (zeilen.results || [])) {
    const tage = (z.bis - jetzt) <= ERINNERUNG_TAGE[1] * TAG ? ERINNERUNG_TAGE[1] : ERINNERUNG_TAGE[0];
    let schon;
    try { schon = await db.prepare('SELECT 1 AS x FROM erinnerung WHERE nutzer_id = ? AND gueltig_bis = ? AND tage = ?').bind(z.nutzer_id, z.bis, tage).first(); } catch (e) { if (fehltTabelle(e)) return ergebnis; throw e; }
    if (schon) continue;
    await db.prepare('INSERT OR IGNORE INTO erinnerung (nutzer_id, gueltig_bis, tage) VALUES (?, ?, ?)').bind(z.nutzer_id, z.bis, tage).run();
    try {
      const p = PRODUKTE[z.stufe];
      let link = '';
      if (paypalEingerichtet(env)) link = dienstUrl(env) + '/bezahlen/verlaengern?t=' + await linkToken(env, z.nutzer_id, z.stufe, jetzt + LINK_TAGE * TAG);
      const rest = Math.max(1, Math.ceil((z.bis - jetzt) / TAG));
      const text = 'Hallo,\n\ndein MobiMory ' + STUFEN[z.stufe].name + ' läuft am ' + datumDe(z.bis) + ' ab (in ' + rest + ' Tag' + (rest === 1 ? '' : 'en') + ').\n\n'
        + 'Wenn du weitermachen möchtest, kannst du für ein weiteres Jahr bezahlen (' + centText(p.cent) + ', also 12 × ' + centText(p.cent / 12) + '):\n'
        + (link ? '\nMit PayPal: ' + link + '\n' : '')
        + '\n' + (appUrl(env) ? 'In der App (' + appUrl(env) + ') geht es unter Konto › Deine Stufe, dort auch per Überweisung.' : 'In der App geht es unter Konto › Deine Stufe, dort auch per Überweisung.')
        + '\n\nEs ist kein Abo: Es wird nichts automatisch abgebucht. Läuft die Zeit ab, bleibt dein Konto auf Basic (1 Fahrzeug, keine Online-Checks). Deine Daten auf dem Gerät bleiben.\n\nWenn du nicht weitermachen möchtest, musst du nichts tun.';
      await mailSenden(env, z.email, 'MobiMory: Dein ' + STUFEN[z.stufe].name + ' läuft bald ab', text);
      ergebnis.gesendet += 1;
    } catch (e) {
      ergebnis.fehler += 1;
      try { await db.prepare('DELETE FROM erinnerung WHERE nutzer_id = ? AND gueltig_bis = ? AND tage = ?').bind(z.nutzer_id, z.bis, tage).run(); } catch (e2) { /* nächster Lauf */ }
    }
  }
  return ergebnis;
}

async function bestellungenAufraeumen(db, jetzt) {
  try {
    await db.batch([
      db.prepare("DELETE FROM bestellung WHERE weg = 'paypal' AND erstellt_am <= ?").bind(jetzt - PAYPAL_BESTELLUNG_TAGE * TAG),
      db.prepare("DELETE FROM bestellung WHERE weg = 'ueberweisung' AND erstellt_am <= ?").bind(jetzt - UEBERWEISUNG_BESTELLUNG_TAGE * TAG),
      db.prepare('DELETE FROM erinnerung WHERE gueltig_bis <= ?').bind(jetzt - 400 * TAG)
    ]);
  } catch (e) { if (!fehltTabelle(e)) throw e; }
}

/* ---------- Freischalt-Seite nur für den Betreiber (Überweisungen) ---------- */

const FREISCHALT_SEITE = '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MobiMory Freischalten</title>'
  + '<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:1rem auto;padding:0 1rem;line-height:1.5}input,select,button{font-size:1rem;padding:.5rem;margin:.2rem 0;max-width:100%}button{cursor:pointer}'
  + '.z{border:1px solid #888;border-radius:.5rem;padding:.6rem;margin:.6rem 0}.m{min-height:1.5rem;font-weight:600}</style></head><body>'
  + '<h1>Freischalten</h1><p>Nur für den Betreiber. Das Passwort bleibt nur in diesem Fenster.</p>'
  + '<p><label>Passwort<br><input type="password" id="pw" autocomplete="current-password"></label></p>'
  + '<p><button id="laden">Offene Überweisungen laden</button></p><p class="m" id="meldung" role="status"></p><div id="liste"></div>'
  + '<h2>Direkt freischalten</h2><p>Wenn Geld ohne Bestellung in der App eingegangen ist.</p>'
  + '<p><label>E-Mail des Kontos<br><input type="email" id="mail"></label></p>'
  + '<p><label>Angebot<br><select id="prod"><option value="mittel">Mittel, ein Jahr</option><option value="voll">Voll, ein Jahr</option><option value="recherche5">5 Recherchen</option><option value="route100">100 Routen</option></select></label></p>'
  + '<p><button id="direkt">Geld ist da: freischalten</button></p>'
  + '<script>(function(){var $=function(i){return document.getElementById(i)};function senden(pfad,body){return fetch(pfad,{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+$("pw").value},body:JSON.stringify(body||{})}).then(function(r){return r.json().then(function(j){if(!r.ok)throw new Error(j&&j.error||("Fehler "+r.status));return j})})}'
  + 'function fehler(e){$("meldung").textContent=String(e&&e.message||e)}'
  + 'function laden(){$("meldung").textContent="";return senden("/freischalten/liste").then(function(j){var l=$("liste");l.textContent="";if(!j.bestellungen.length){$("meldung").textContent="Keine offenen Überweisungen.";return}j.bestellungen.forEach(function(b){var d=document.createElement("div");d.className="z";d.appendChild(document.createTextNode(b.id+" · "+b.email+" · "+b.angebot+" · "+b.betrag+" · bestellt "+b.datum));d.appendChild(document.createElement("br"));var k=document.createElement("button");k.textContent="Geld ist da: freischalten";k.onclick=function(){if(!confirm("Freischalten: "+b.email+", "+b.angebot+"?"))return;senden("/freischalten/bestaetigen",{referenz:b.id}).then(function(r){$("meldung").textContent="Freigeschaltet, Beleg "+r.nummer;return laden()}).catch(fehler)};var x=document.createElement("button");x.textContent="Löschen";x.onclick=function(){if(!confirm("Bestellung "+b.id+" löschen?"))return;senden("/freischalten/loeschen",{referenz:b.id}).then(laden).catch(fehler)};d.appendChild(k);d.appendChild(x);l.appendChild(d)})}).catch(fehler)}'
  + '$("laden").onclick=laden;$("direkt").onclick=function(){if(!confirm("Freischalten: "+$("mail").value+"?"))return;senden("/freischalten/direkt",{email:$("mail").value,produkt:$("prod").value}).then(function(r){$("meldung").textContent="Freigeschaltet, Beleg "+r.nummer}).catch(fehler)}})();<\/script></body></html>';

async function freischaltSeite() {
  return new Response(FREISCHALT_SEITE, { status: 200, headers: Object.assign({}, SEITE_KOPF, { 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'", 'X-Robots-Tag': 'noindex' }) });
}

async function adminPruefen(request, env, db, jetzt) {
  const soll = adminToken(env);
  if (!soll) throw new HttpFehler(503, 'Die Freischalt-Seite ist im Dienst nicht eingerichtet (Geheimnis FREISCHALT_TOKEN fehlt oder ist zu kurz).');
  const m = /^Bearer (.{1,300})$/.exec(request.headers.get('Authorization') || '');
  const ok = m && gleich(await hmac(pepper(env), 'admin:' + m[1]), await hmac(pepper(env), 'admin:' + soll));
  if (!ok) {
    await bremsen(db, await schluesselFuer('adm', request.headers.get('CF-Connecting-IP') || 'unbekannt'), 8, 15 * MINUTE, jetzt, 'Zu viele falsche Versuche.');
    throw new HttpFehler(401, 'Das Passwort stimmt nicht.');
  }
}

/* Die vier Arbeiten der Freischaltung. Sie prüfen die Berechtigung nicht selbst: Die Freischalt-Seite (Passwort) und die Verwaltung in der App (Rolle Admin, seit 13f-11)
   rufen sie nach ihrer eigenen Prüfung auf. */
async function freischaltListeKern(db) {
  const z = await db.prepare("SELECT * FROM bestellung WHERE weg = 'ueberweisung' ORDER BY erstellt_am LIMIT 200").all();
  return { ok: true, bestellungen: (z.results || []).map((r) => ({ id: r.id, email: r.email, angebot: (PRODUKTE[r.produkt] ? PRODUKTE[r.produkt].kurz : r.produkt) + (r.gutschein ? ' mit Code ' + codeAnzeige(r.gutschein) : ''), betrag: centText(r.cent), datum: datumDe(r.erstellt_am) })) };
}

async function freischaltBestaetigenKern(request, env, db, jetzt) {
  const b = await bodyLesen(request, MAX_BODY);
  const ref = typeof b.referenz === 'string' ? b.referenz.toUpperCase().trim() : '';
  const best = /^MM-[A-Z0-9]{8}$/.test(ref) ? await db.prepare("SELECT * FROM bestellung WHERE id = ? AND weg = 'ueberweisung'").bind(ref).first() : null;
  if (!best) throw new HttpFehler(404, 'Diese Bestellung gibt es nicht (mehr).');
  const erg = await bestellungAbschliessen(env, db, best, 'ueberweisung', best.id, jetzt);
  return { ok: true, nummer: erg.nummer, bis: erg.bis };
}

async function freischaltDirektKern(request, env, db, jetzt) {
  const b = await bodyLesen(request, MAX_BODY);
  const email = emailNormal(b.email);
  const { id, p } = produktVon(b.produkt);
  const n = await db.prepare('SELECT id, email FROM nutzer WHERE lower(email) = ? AND bestaetigt_am IS NOT NULL').bind(email).first();
  if (!n) throw new HttpFehler(404, 'Zu dieser E-Mail-Adresse gibt es kein bestätigtes Konto.');
  await bestellPruefen(db, n.id, id, jetzt);
  const bid = await bestellungAnlegen(db, n, id, 'ueberweisung', jetzt);
  const erg = await bestellungAbschliessen(env, db, { id: bid, nutzer_id: n.id, email: n.email, produkt: id, cent: p.cent }, 'ueberweisung', bid, jetzt);
  return { ok: true, nummer: erg.nummer, bis: erg.bis };
}

async function freischaltLoeschenKern(request, db) {
  const b = await bodyLesen(request, MAX_BODY);
  const ref = typeof b.referenz === 'string' ? b.referenz.toUpperCase().trim() : '';
  if (!/^MM-[A-Z0-9]{8}$/.test(ref)) throw new HttpFehler(400, 'Die Bestellnummer ist ungültig.');
  await db.prepare("DELETE FROM bestellung WHERE id = ? AND weg = 'ueberweisung'").bind(ref).run();
  return { ok: true };
}

/* Die Freischalt-Seite im Browser (Passwort FREISCHALT_TOKEN), unverändert. */
async function freischaltListe(request, env, db, jetzt) { await adminPruefen(request, env, db, jetzt); return freischaltListeKern(db); }
async function freischaltBestaetigen(request, env, db, jetzt) { await adminPruefen(request, env, db, jetzt); return freischaltBestaetigenKern(request, env, db, jetzt); }
async function freischaltDirekt(request, env, db, jetzt) { await adminPruefen(request, env, db, jetzt); return freischaltDirektKern(request, env, db, jetzt); }
async function freischaltLoeschen(request, env, db, jetzt) { await adminPruefen(request, env, db, jetzt); return freischaltLoeschenKern(request, db); }

/* ---------- 13f-11: Verwaltung in der App (seit 2.0.94) ---------- */

/* Festlegung des Nutzers (15.11.2026): Die Kachel „Verwaltung“ im Bereich „Nur für Entwickler“ zeigt die Statistik (Konten insgesamt, davon Test, Mittel, Voll) und
   bucht Zahlungseingänge von Überweisungen (Freischaltung). Die Statistik sehen Admin und Entwickler, Buchen und Freischalten dürfen nur Admins (wie bei den Gutscheincodes).
   Angemeldet wird wie sonst mit der Anmeldung der App, ein zweites Passwort gibt es dafür nicht. Die Seite /freischalten mit Passwort bleibt daneben bestehen. */
async function verwaltungPruefen(request, db, jetzt, nurAdminErlaubt) {
  const a = await authentifizieren(request, db, jetzt);
  const r = await rolleVon(db, a.email);
  if (!r || (nurAdminErlaubt && r !== 'admin')) throw new HttpFehler(403, nurAdminErlaubt ? 'Zahlungseingänge buchen und freischalten dürfen nur Administratoren.' : 'Die Verwaltung sehen nur Administratoren und Entwickler.');
  return a;
}

/* Gezählt werden bestätigte Konten nach der Stufe, die sie heute haben (dieselbe Regel wie stufeVon: bezahlt und gültig, sonst laufende Testwoche, sonst Basic). */
async function verwaltungStatistik(request, env, db, jetzt) {
  await verwaltungPruefen(request, db, jetzt, false);
  let z, abg;
  try {
    z = await db.prepare("SELECT CASE WHEN s.stufe IN ('mittel', 'voll', 'entwickler') AND (s.gueltig_bis IS NULL OR s.gueltig_bis > ?) THEN s.stufe "
      + "WHEN EXISTS (SELECT 1 FROM testwoche t WHERE t.nutzer_id = n.id AND t.ende_am > ?) THEN 'test' ELSE 'basic' END AS st, COUNT(*) AS n "
      + 'FROM nutzer n LEFT JOIN stufe_konto s ON s.nutzer_id = n.id WHERE n.bestaetigt_am IS NOT NULL GROUP BY st').bind(jetzt, jetzt).all();
    abg = await db.prepare("SELECT COUNT(*) AS n FROM stufe_konto s JOIN nutzer n ON n.id = s.nutzer_id WHERE n.bestaetigt_am IS NOT NULL AND s.stufe IN ('mittel', 'voll') AND s.gueltig_bis IS NOT NULL AND s.gueltig_bis <= ?").bind(jetzt).first();
  } catch (e) { if (fehltTabelle(e)) throw new HttpFehler(503, 'Die Tabellen für die Stufen fehlen noch (Update auf 13e, siehe server/EINRICHTUNG.md).'); throw e; }
  const nach = { test: 0, basic: 0, mittel: 0, voll: 0, entwickler: 0 };
  (z.results || []).forEach((r) => { if (r.st in nach) nach[r.st] = r.n; });
  const konten = nach.test + nach.basic + nach.mittel + nach.voll + nach.entwickler;
  return { ok: true, stand: datumDe(jetzt), konten, test: nach.test, mittel: nach.mittel, voll: nach.voll, entwickler: nach.entwickler, basic: nach.basic, abgelaufen: abg ? abg.n : 0 };
}

async function verwaltungBestellungen(request, env, db, jetzt) { await verwaltungPruefen(request, db, jetzt, true); return freischaltListeKern(db); }
async function verwaltungBestaetigen(request, env, db, jetzt) { await verwaltungPruefen(request, db, jetzt, true); return freischaltBestaetigenKern(request, env, db, jetzt); }
async function verwaltungDirekt(request, env, db, jetzt) { await verwaltungPruefen(request, db, jetzt, true); return freischaltDirektKern(request, env, db, jetzt); }
async function verwaltungLoeschen(request, env, db, jetzt) { await verwaltungPruefen(request, db, jetzt, true); return freischaltLoeschenKern(request, db); }

/* ---------- 13e-3: Kosten-Wächter für die Testwochen (seit 2.0.71) ---------- */

/* Standardwerte (Nutzer, 12.11.2026). Alles lässt sich als Variable im Konto-Worker ändern, ohne neue Version:
     KOSTEN_CHECK            Kosten eines Online-Checks in Euro (Standard 0,45; nur eine Schätzung, der echte Wert kommt aus der OpenAI-Abrechnung)
     WAECHTER_ANTEIL         Warnung, wenn die Testwochen-Kosten diesen Anteil der Einnahmen überschreiten (Standard 0,2 = 20 %)
     WAECHTER_TAGE           Zeitraum für die Rechnung in Tagen (Standard 30)
     WAECHTER_CHECKS_TAG     Solange es keine Einnahmen gibt: höchstens so viele Testwochen-Checks in 24 Stunden (Standard 10)
     WAECHTER_TESTWOCHEN_TAG Höchstens so viele neue Testwochen in 24 Stunden (Standard 5)
     WAECHTER_EMAIL          Empfänger der Warnung (ohne sie wird nur geprüft und ins Protokoll geschrieben)
     WAECHTER_AUSGENOMMEN    Mail-Adressen, durch Komma getrennt, die nicht mitzählen: eigene Test-Konten und geschenkte Voll-Konten
   Das Konto mit der Stufe „entwickler“ zählt nie mit. */
export const WAECHTER_STANDARD = { kostenCheck: 0.45, anteil: 0.2, tage: 30, checksTag: 10, testwochenTag: 5 };
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
    /* Einnahmen (seit 2.0.72): die echten Belege der letzten 365 Tage, durch 12 geteilt, damit eine Jahreszahlung nicht nur in einem Monat zählt.
       Belege der ausgenommenen Adressen zählen nicht. Fehlt die Tabelle noch, gibt es keine Einnahmen. */
    let umsatzCent = 0;
    try {
      const u = await db.prepare('SELECT COALESCE(SUM(cent), 0) AS s FROM beleg WHERE am > ?' + (aus.length ? ' AND lower(email) NOT IN (' + platz + ')' : ''))
        .bind(jetzt - 365 * TAG, ...aus).first();
      umsatzCent = u ? Number(u.s) : 0;
    } catch (e) { if (!fehltTabelle(e)) throw e; }
    const einnahmenMonat = umsatzCent / 100 / 12;
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
    + '- Einnahmen (Belege der letzten 365 Tage, durch 12 geteilt, auf den Zeitraum umgerechnet): ' + euroText(w.einnahmenZeitraum) + ' im Zeitraum');
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
  /* Cron-Auslöser (wrangler-konto.jsonc, alle 15 Minuten): der Kosten-Wächter und die Erinnerungen vor dem Ablauf. Fehler stören nichts anderes, sie stehen im Protokoll. */
  scheduled(event, env, ctx) {
    const lauf = waechterPruefen(env, datenbank(env), Date.now()).then((r) => {
      console.log('Kosten-Wächter: geprüft=' + r.geprueft + ' Warnung=' + r.warnung + ' Gründe=' + r.gruende.join(',') + ' Mail=' + r.mail);
    }).catch((e) => { console.log('Kosten-Wächter: Fehler ' + String(e && e.message || e)); })
      .then(() => bestellungenAufraeumen(datenbank(env), Date.now()))
      .then(() => erinnerungenSenden(env, datenbank(env), Date.now()))
      .then((r) => { if (r.gesendet || r.fehler) console.log('Erinnerungen: gesendet=' + r.gesendet + ' fehlgeschlagen=' + r.fehler); })
      .catch((e) => { console.log('Erinnerungen: Fehler ' + String(e && e.message || e)); });
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(lauf);
    return lauf;
  }
};
