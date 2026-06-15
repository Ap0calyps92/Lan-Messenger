import tkinter as tk
from tkinter import simpledialog, scrolledtext, filedialog, ttk
import socket
import threading
import json
import os
import base64
import io
import struct
import logging
import uuid
import time
from datetime import datetime

try:
    from PIL import Image, ImageTk, ImageSequence

    PILLOW_OK = True
except ImportError:
    PILLOW_OK = False

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import secrets

    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(
            os.path.join(os.path.expanduser("~"), "messenger.log"), encoding="utf-8"
        ),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("messenger")

# ──────────────────────────────────────────────
# Konstanten
# ──────────────────────────────────────────────
VERSION = 5
PORT = 9999
MAX_GIF_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 100 * 1024 * 1024  # 100 MB
FILE_CHUNK_SIZE = 64 * 1024  # 64 KB pro Chunk
SCAN_INTERVAL = 15_000
RECONNECT_DELAY = 5_000
TIPP_TIMEOUT = 4_000
TOAST_DAUER = 4_000

eigene_ip = socket.gethostbyname(socket.gethostname())
benutzername = ""
aktive_hosts = {}  # ip -> name
letzter_kontakt = {}  # ip -> timestamp (float)
chat_verlaeufe = {}  # ip -> [eintrag, ...]
aktiver_chat = None
ungelesene = set()
laufende_animationen = {}
tipp_timers = {}  # ip -> after-id

# ── NEU: Message-ID Tracking ──
pending_receipts = (
    {}
)  # msg_id -> {"ip": ip, "widget_id": widget_id}  (auf Bestätigung wartend)
msg_widgets = {}  # msg_id -> tk.Label  (Status-Label im Chat)

HOME = os.path.expanduser("~")
SPEICHER_DATEI = os.path.join(HOME, "messenger_verlauf.json")
CONFIG_DATEI = os.path.join(HOME, "messenger_config.json")
GIF_ORDNER = os.path.join(HOME, "messenger_gifs")
FILE_ORDNER = os.path.join(HOME, "messenger_files")
os.makedirs(GIF_ORDNER, exist_ok=True)
os.makedirs(FILE_ORDNER, exist_ok=True)

if CRYPTO_OK:
    _privkey = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    _pubkey_pem = (
        _privkey.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
else:
    _privkey = None
    _pubkey_pem = ""

peer_pubkeys = {}  # ip -> public_key_object

# ── Locks für Thread-Safety ──
_hosts_lock = threading.Lock()
_pubkey_lock = threading.Lock()


# ══════════════════════════════════════════════
# Konfiguration
# ══════════════════════════════════════════════


def config_laden():
    if os.path.exists(CONFIG_DATEI):
        try:
            with open(CONFIG_DATEI, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log.warning(f"Config laden: {e}")
    return {}


def config_speichern(daten: dict):
    try:
        with open(CONFIG_DATEI, "w", encoding="utf-8") as f:
            json.dump(daten, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log.warning(f"Config speichern: {e}")


# ══════════════════════════════════════════════
# Verlauf
# ══════════════════════════════════════════════


def verlauf_laden():
    global chat_verlaeufe
    if os.path.exists(SPEICHER_DATEI):
        try:
            with open(SPEICHER_DATEI, "r", encoding="utf-8") as f:
                chat_verlaeufe = json.load(f)
        except Exception as e:
            log.warning(f"Verlauf laden: {e}")
            chat_verlaeufe = {}


def verlauf_speichern():
    try:
        with open(SPEICHER_DATEI, "w", encoding="utf-8") as f:
            json.dump(chat_verlaeufe, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log.warning(f"Verlauf speichern: {e}")


def nachricht_speichern(ip: str, eintrag: dict):
    if ip not in chat_verlaeufe:
        chat_verlaeufe[ip] = []
    chat_verlaeufe[ip].append(eintrag)
    verlauf_speichern()


def eintrag_aktualisieren(ip: str, msg_id: str, updates: dict):
    """Findet einen Eintrag anhand msg_id und überschreibt Felder."""
    for eintrag in chat_verlaeufe.get(ip, []):
        if eintrag.get("msg_id") == msg_id:
            eintrag.update(updates)
            break
    verlauf_speichern()


# ══════════════════════════════════════════════
# Verschlüsselung
# ══════════════════════════════════════════════


def verschluesseln(nachricht_bytes: bytes, peer_ip: str) -> dict | None:
    if not CRYPTO_OK or peer_ip not in peer_pubkeys:
        return None
    try:
        aes_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend()
        )
        enc = cipher.encryptor()
        ct = enc.update(nachricht_bytes) + enc.finalize()
        enc_key = peer_pubkeys[peer_ip].encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
        return {
            "enc_key": base64.b64encode(enc_key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode(),
            "tag": base64.b64encode(enc.tag).decode(),
        }
    except Exception as e:
        log.error(f"Verschlüsseln: {e}")
        return None


def entschluesseln(payload: dict) -> bytes | None:
    if not CRYPTO_OK or not _privkey:
        return None
    try:
        aes_key = _privkey.decrypt(
            base64.b64decode(payload["enc_key"]),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(
                base64.b64decode(payload["nonce"]), base64.b64decode(payload["tag"])
            ),
            backend=default_backend(),
        )
        dec = cipher.decryptor()
        return dec.update(base64.b64decode(payload["ct"])) + dec.finalize()
    except Exception as e:
        log.error(f"Entschlüsseln: {e}")
        return None


# ══════════════════════════════════════════════
# Length-Prefix Protokoll
# ══════════════════════════════════════════════


def send_paket(sock: socket.socket, daten: dict):
    raw = json.dumps(daten, ensure_ascii=False).encode("utf-8")
    header = struct.pack(">I", len(raw))
    sock.sendall(header + raw)


def recv_paket(sock: socket.socket) -> dict | None:
    try:
        header = _recv_genau(sock, 4)
        if not header:
            return None
        laenge = struct.unpack(">I", header)[0]
        if laenge > 200 * 1024 * 1024:
            return None
        raw = _recv_genau(sock, laenge)
        return json.loads(raw.decode("utf-8")) if raw else None
    except Exception as e:
        log.debug(f"recv_paket: {e}")
        return None


def _recv_genau(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ══════════════════════════════════════════════
# Ton (plattformunabhängig)
# ══════════════════════════════════════════════


def ton_abspielen():
    try:
        if os.name == "nt":
            import winsound

            winsound.MessageBeep(winsound.MB_ICONASTERISK)
        else:
            os.system(
                "paplay /usr/share/sounds/freedesktop/stereo/message.oga 2>/dev/null &"
            )
    except Exception:
        pass


# ══════════════════════════════════════════════
# Toast
# ══════════════════════════════════════════════


def toast_anzeigen(titel: str, text: str):
    toast = tk.Toplevel(fenster)
    toast.overrideredirect(True)
    toast.attributes("-topmost", True)
    toast.configure(bg=C_PANEL)
    breite, hoehe = 280, 70
    sx = fenster.winfo_screenwidth()
    sy = fenster.winfo_screenheight()
    toast.geometry(f"{breite}x{hoehe}+{sx - breite - 20}+{sy - hoehe - 60}")
    tk.Label(
        toast,
        text=titel,
        font=("Segoe UI", 10, "bold"),
        bg=C_PANEL,
        fg=C_NAME_IN,
        anchor="w",
    ).pack(fill="x", padx=12, pady=(8, 0))
    tk.Label(
        toast,
        text=text[:60] + ("…" if len(text) > 60 else ""),
        font=("Segoe UI", 9),
        bg=C_PANEL,
        fg=C_TEXT,
        anchor="w",
        wraplength=256,
    ).pack(fill="x", padx=12)

    def schliessen():
        try:
            toast.destroy()
        except Exception:
            pass

    toast.after(TOAST_DAUER, schliessen)
    toast.bind("<Button-1>", lambda e: schliessen())


# ══════════════════════════════════════════════
# Tipp-Indikator
# ══════════════════════════════════════════════


def tipp_signal_senden(event=None):
    ziel_ip = aktiver_chat
    if not ziel_ip:
        return
    if hasattr(tipp_signal_senden, "_last") and tipp_signal_senden._last == ziel_ip:
        return
    tipp_signal_senden._last = ziel_ip

    def sende():
        try:
            s = _verbinden(ziel_ip, timeout=1.0)
            if s:
                send_paket(s, {"version": VERSION, "typ": "tipp", "name": benutzername})
                s.close()
        except Exception:
            pass
        tipp_signal_senden._last = None

    threading.Thread(target=sende, daemon=True).start()


_tipp_reset_timer = [None]


def tipp_reset_starten(event=None):
    if _tipp_reset_timer[0]:
        fenster.after_cancel(_tipp_reset_timer[0])
    _tipp_reset_timer[0] = fenster.after(
        3000, lambda: setattr(tipp_signal_senden, "_last", None)
    )


def tipp_anzeigen(peer_ip: str):
    name = aktive_hosts.get(peer_ip, peer_ip)
    if peer_ip == aktiver_chat:
        tipp_label.config(text=f"✏ {name} tippt...")
    if peer_ip in tipp_timers:
        fenster.after_cancel(tipp_timers[peer_ip])
    tipp_timers[peer_ip] = fenster.after(TIPP_TIMEOUT, lambda: tipp_ausblenden(peer_ip))


def tipp_ausblenden(peer_ip: str):
    tipp_timers.pop(peer_ip, None)
    if peer_ip == aktiver_chat:
        tipp_label.config(text="")


# ══════════════════════════════════════════════
# NEU: Online-Status
# ══════════════════════════════════════════════


def online_status_text(ip: str) -> str:
    """Gibt 'Online' oder 'Zuletzt gesehen um HH:MM' zurück."""
    ts = letzter_kontakt.get(ip)
    if ts is None:
        return ""
    delta = time.time() - ts
    if delta < 60:
        return "🟢 Online"
    zeitstr = datetime.fromtimestamp(ts).strftime("%H:%M")
    if delta < 86400:
        return f"⚫ Zuletzt gesehen um {zeitstr}"
    datumstr = datetime.fromtimestamp(ts).strftime("%d.%m. %H:%M")
    return f"⚫ Zuletzt gesehen am {datumstr}"


def online_status_aktualisieren():
    """Aktualisiert den Status-Text im Chat-Kopf alle 30s."""
    if aktiver_chat:
        status_text = online_status_text(aktiver_chat)
        online_label.config(text=status_text)
    fenster.after(30_000, online_status_aktualisieren)


# ══════════════════════════════════════════════
# GIF
# ══════════════════════════════════════════════


def gif_speichern(gif_bytes: bytes, peer_ip: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    dateiname = f"{peer_ip}_{ts}.gif"
    with open(os.path.join(GIF_ORDNER, dateiname), "wb") as f:
        f.write(gif_bytes)
    return dateiname


def gif_bytes_laden(dateiname: str) -> bytes | None:
    pfad = os.path.join(GIF_ORDNER, dateiname)
    if os.path.exists(pfad):
        with open(pfad, "rb") as f:
            return f.read()
    return None


def gif_animieren(anim_id: int):
    if anim_id not in laufende_animationen:
        return
    anim = laufende_animationen[anim_id]
    try:
        anim["label"].config(image=anim["frames"][anim["idx"]])
        anim["idx"] = (anim["idx"] + 1) % len(anim["frames"])
        fenster.after(anim["delays"][anim["idx"]], gif_animieren, anim_id)
    except Exception:
        laufende_animationen.pop(anim_id, None)


def gif_einfuegen(parent_frame: tk.Frame, gif_bytes: bytes):
    if not PILLOW_OK:
        tk.Label(parent_frame, text="[GIF — Pillow fehlt]", bg=C_BG, fg=C_DANGER).pack(
            anchor="w"
        )
        return
    try:
        img = Image.open(io.BytesIO(gif_bytes))
        frames, delays = [], []
        for frame in ImageSequence.Iterator(img):
            f = frame.convert("RGBA").resize(
                (min(frame.width, 300), min(frame.height, 200)), Image.LANCZOS
            )
            frames.append(ImageTk.PhotoImage(f))
            delays.append(frame.info.get("duration", 100))
        lbl = tk.Label(parent_frame, bg=C_BG, cursor="hand2")
        lbl.pack(anchor="w", pady=2)
        anim_id = id(lbl)
        laufende_animationen[anim_id] = {
            "frames": frames,
            "delays": delays,
            "idx": 0,
            "label": lbl,
        }
        gif_animieren(anim_id)
    except Exception as e:
        tk.Label(parent_frame, text=f"[GIF-Fehler: {e}]", bg=C_BG, fg=C_DANGER).pack(
            anchor="w"
        )


# ══════════════════════════════════════════════
# NEU: Datei speichern/laden
# ══════════════════════════════════════════════


def datei_empfangen_speichern(datei_bytes: bytes, dateiname: str) -> str:
    """Speichert empfangene Datei im FILE_ORDNER, gibt Pfad zurück."""
    # Sicherheitscheck: kein Pfad-Traversal
    sicherer_name = os.path.basename(dateiname)
    ziel_pfad = os.path.join(FILE_ORDNER, sicherer_name)
    # Doppelte Dateien umbenennen
    basis, ext = os.path.splitext(sicherer_name)
    zaehler = 1
    while os.path.exists(ziel_pfad):
        ziel_pfad = os.path.join(FILE_ORDNER, f"{basis}_{zaehler}{ext}")
        zaehler += 1
    with open(ziel_pfad, "wb") as f:
        f.write(datei_bytes)
    return ziel_pfad


# ══════════════════════════════════════════════
# Netzwerk-Scan
# ══════════════════════════════════════════════


def get_netz_prefix() -> str:
    return ".".join(eigene_ip.split(".")[:3]) + "."


def scan_netz():
    from concurrent.futures import ThreadPoolExecutor

    prefix = get_netz_prefix()

    def check(ip: str):
        if ip == eigene_ip:
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, PORT))
            send_paket(
                s,
                {
                    "version": VERSION,
                    "typ": "ping",
                    "name": benutzername,
                    "ip": eigene_ip,
                    "pubkey": _pubkey_pem if CRYPTO_OK else "",
                },
            )
            antwort = recv_paket(s)
            if antwort:
                with _hosts_lock:
                    aktive_hosts[ip] = antwort.get("name", ip)
                    letzter_kontakt[ip] = time.time()
                if CRYPTO_OK and antwort.get("pubkey"):
                    with _pubkey_lock:
                        peer_pubkeys[ip] = serialization.load_pem_public_key(
                            antwort["pubkey"].encode(), backend=default_backend()
                        )
            s.close()
        except Exception:
            with _hosts_lock:
                aktive_hosts.pop(ip, None)
            with _pubkey_lock:
                peer_pubkeys.pop(ip, None)

    with ThreadPoolExecutor(max_workers=32) as pool:
        pool.map(check, [f"{prefix}{i}" for i in range(1, 255)])

    aktualisiere_dropdown()
    fenster.after(SCAN_INTERVAL, scan_netz)


# ══════════════════════════════════════════════
# Server
# ══════════════════════════════════════════════


def server_starten():
    while True:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", PORT))
            server.listen(10)
            while True:
                try:
                    conn, addr = server.accept()
                    threading.Thread(
                        target=verbindung_behandeln, args=(conn, addr), daemon=True
                    ).start()
                except Exception as e:
                    log.warning(f"Accept: {e}")
                    break
        except Exception as e:
            log.error(f"Server-Fehler: {e}")
            import time as _t

            _t.sleep(RECONNECT_DELAY / 1000)


def verbindung_behandeln(conn: socket.socket, addr):
    peer_ip = addr[0]
    try:
        conn.settimeout(30)
        msg = recv_paket(conn)
        if not msg:
            return
        sender_version = msg.get("version", 1)
        typ = msg.get("typ", "")

        # ── Timestamp aktualisieren bei jedem Kontakt ──
        letzter_kontakt[peer_ip] = time.time()

        if typ == "ping":
            if CRYPTO_OK and msg.get("pubkey"):
                try:
                    with _pubkey_lock:
                        peer_pubkeys[peer_ip] = serialization.load_pem_public_key(
                            msg["pubkey"].encode(), backend=default_backend()
                        )
                except Exception as e:
                    log.warning(f"Pubkey {peer_ip}: {e}")
            send_paket(
                conn,
                {
                    "version": VERSION,
                    "name": benutzername,
                    "pubkey": _pubkey_pem if CRYPTO_OK else "",
                },
            )
            with _hosts_lock:
                aktive_hosts[peer_ip] = msg.get("name", peer_ip)
            aktualisiere_dropdown()

        elif typ == "tipp":
            absender_name = msg.get("name", peer_ip)
            with _hosts_lock:
                if peer_ip not in aktive_hosts:
                    aktive_hosts[peer_ip] = absender_name
            fenster.after(0, lambda ip=peer_ip: tipp_anzeigen(ip))

        # ── NEU: Read Receipt empfangen ──
        elif typ == "gelesen":
            msg_id = msg.get("msg_id")
            if msg_id:
                fenster.after(0, lambda mid=msg_id: receipt_markieren(mid, "gelesen"))

        elif typ == "empfangen":
            msg_id = msg.get("msg_id")
            if msg_id:
                fenster.after(0, lambda mid=msg_id: receipt_markieren(mid, "empfangen"))

        # ── NEU: Nachricht löschen ──
        elif typ == "loeschen":
            msg_id = msg.get("msg_id")
            if msg_id:
                eintrag_aktualisieren(
                    peer_ip, msg_id, {"text": "[Nachricht gelöscht]", "geloescht": True}
                )
                fenster.after(
                    0,
                    lambda mid=msg_id: chat_eintrag_ui_aktualisieren(
                        mid, "[Nachricht gelöscht]", geloescht=True
                    ),
                )

        # ── NEU: Nachricht bearbeiten ──
        elif typ == "bearbeiten":
            msg_id = msg.get("msg_id")
            neuer_text = msg.get("text", "")
            if msg_id and neuer_text:
                eintrag_aktualisieren(
                    peer_ip, msg_id, {"text": neuer_text, "bearbeitet": True}
                )
                fenster.after(
                    0,
                    lambda mid=msg_id, t=neuer_text: chat_eintrag_ui_aktualisieren(
                        mid, t, bearbeitet=True
                    ),
                )

        elif typ in ("nachricht", "gif", "gruppe"):
            absender_name = msg.get("name", peer_ip)
            msg_id = msg.get("msg_id", str(uuid.uuid4()))
            zeit = datetime.now().strftime("%H:%M")
            version_hinweis = (
                f" [v{sender_version}]" if sender_version != VERSION else ""
            )
            encrypted = msg.get("encrypted", False)
            ist_gruppe = typ == "gruppe"

            with _hosts_lock:
                if peer_ip not in aktive_hosts:
                    aktive_hosts[peer_ip] = absender_name
                    aktualisiere_dropdown()

            if typ in ("nachricht", "gruppe"):
                if encrypted and CRYPTO_OK:
                    raw = entschluesseln(msg["payload"])
                    text = (
                        raw.decode("utf-8")
                        if raw
                        else "[Entschlüsselung fehlgeschlagen]"
                    )
                else:
                    text = msg.get("text", "")
                eintrag = {
                    "msg_id": msg_id,
                    "typ": "text",
                    "zeit": zeit,
                    "name": absender_name + version_hinweis,
                    "text": text,
                    "eingehend": True,
                    "encrypted": encrypted,
                    "gruppe": ist_gruppe,
                }
            else:  # gif
                if encrypted and CRYPTO_OK:
                    raw = entschluesseln(msg["payload"])
                    gif_bytes = raw if raw else b""
                else:
                    gif_bytes = base64.b64decode(msg.get("gif_b64", ""))
                dateiname = gif_speichern(gif_bytes, peer_ip)
                eintrag = {
                    "msg_id": msg_id,
                    "typ": "gif",
                    "zeit": zeit,
                    "name": absender_name + version_hinweis,
                    "gif_datei": dateiname,
                    "eingehend": True,
                    "encrypted": encrypted,
                    "gruppe": False,
                }

            nachricht_speichern(peer_ip, eintrag)
            fenster.after(0, lambda e=eintrag, ip=peer_ip: eingehende_nachricht(ip, e))

            # Read Receipt: "empfangen" sofort zurückschicken
            def sende_empfangen_receipt(ziel_ip=peer_ip, mid=msg_id):
                try:
                    s = _verbinden(ziel_ip, timeout=3.0)
                    if s:
                        send_paket(
                            s, {"version": VERSION, "typ": "empfangen", "msg_id": mid}
                        )
                        s.close()
                except Exception:
                    pass

            threading.Thread(target=sende_empfangen_receipt, daemon=True).start()

        # ── NEU: Dateiübertragung ──
        elif typ == "datei":
            absender_name = msg.get("name", peer_ip)
            msg_id = msg.get("msg_id", str(uuid.uuid4()))
            dateiname = msg.get("dateiname", "unbekannte_datei")
            dateigroesse = msg.get("dateigroesse", 0)
            encrypted = msg.get("encrypted", False)
            zeit = datetime.now().strftime("%H:%M")

            if dateigroesse > MAX_FILE_BYTES:
                log.warning(f"Datei zu groß von {peer_ip}: {dateigroesse}")
                return

            # Dateidaten empfangen (Base64 im Paket)
            if encrypted and CRYPTO_OK:
                raw = entschluesseln(msg["payload"])
                datei_bytes = raw if raw else b""
            else:
                datei_bytes = base64.b64decode(msg.get("datei_b64", ""))

            gespeicherter_pfad = datei_empfangen_speichern(datei_bytes, dateiname)

            with _hosts_lock:
                if peer_ip not in aktive_hosts:
                    aktive_hosts[peer_ip] = absender_name
                    aktualisiere_dropdown()

            eintrag = {
                "msg_id": msg_id,
                "typ": "datei",
                "zeit": zeit,
                "name": absender_name,
                "dateiname": dateiname,
                "datei_pfad": gespeicherter_pfad,
                "dateigroesse": dateigroesse,
                "eingehend": True,
                "encrypted": encrypted,
                "gruppe": False,
            }
            nachricht_speichern(peer_ip, eintrag)
            fenster.after(0, lambda e=eintrag, ip=peer_ip: eingehende_nachricht(ip, e))

    except Exception as e:
        log.warning(f"Verbindung {peer_ip}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def eingehende_nachricht(peer_ip: str, eintrag: dict):
    name = aktive_hosts.get(peer_ip, peer_ip)
    text_vorschau = eintrag.get("text", "[Datei/GIF]")
    if peer_ip != aktiver_chat or not fenster.focus_displayof():
        ton_abspielen()
        toast_anzeigen(f"Nachricht von {name}", text_vorschau)
    nachricht_in_chat_einfuegen(peer_ip, eintrag)
    tipp_ausblenden(peer_ip)
    # Wenn der Chat gerade offen ist → "gelesen" schicken
    if peer_ip == aktiver_chat and fenster.focus_displayof():
        _gelesen_receipt_senden(peer_ip, eintrag.get("msg_id", ""))


def _gelesen_receipt_senden(ziel_ip: str, msg_id: str):
    if not msg_id:
        return

    def sende():
        try:
            s = _verbinden(ziel_ip, timeout=3.0)
            if s:
                send_paket(s, {"version": VERSION, "typ": "gelesen", "msg_id": msg_id})
                s.close()
        except Exception:
            pass

    threading.Thread(target=sende, daemon=True).start()


# ══════════════════════════════════════════════
# NEU: Read Receipt UI
# ══════════════════════════════════════════════


def receipt_markieren(msg_id: str, status: str):
    """Aktualisiert das Receipt-Label einer gesendeten Nachricht."""
    lbl = msg_widgets.get(msg_id)
    if not lbl:
        return
    if status == "empfangen":
        lbl.config(text=" ✓✓", fg=C_TEXT_DIM)
    elif status == "gelesen":
        lbl.config(text=" 👁", fg=C_ACCENT)


# ══════════════════════════════════════════════
# Senden
# ══════════════════════════════════════════════


def _verbinden(ziel_ip: str, timeout: float = 5.0) -> socket.socket | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ziel_ip, PORT))
        return s
    except Exception as e:
        log.warning(f"Verbinden {ziel_ip}: {e}")
        return None


def _nachricht_paket_bauen(
    text: str, ziel_ip: str, typ: str = "nachricht", msg_id: str = None
) -> dict:
    if msg_id is None:
        msg_id = str(uuid.uuid4())
    encrypted = CRYPTO_OK and ziel_ip in peer_pubkeys
    if encrypted:
        return {
            "version": VERSION,
            "typ": typ,
            "name": benutzername,
            "msg_id": msg_id,
            "encrypted": True,
            "payload": verschluesseln(text.encode("utf-8"), ziel_ip),
        }
    return {
        "version": VERSION,
        "typ": typ,
        "name": benutzername,
        "msg_id": msg_id,
        "encrypted": False,
        "text": text,
    }


def senden(event=None):
    ziel_ip = aktiver_chat
    text = nachricht_eingabe.get("1.0", tk.END).strip()
    if not ziel_ip or not text:
        return "break"

    msg_id = str(uuid.uuid4())

    def send_thread():
        s = _verbinden(ziel_ip)
        if not s:
            fenster.after(
                0,
                lambda: status_label.config(
                    text=f"⚠ {ziel_ip} nicht erreichbar", fg=C_DANGER
                ),
            )
            fenster.after(RECONNECT_DELAY, lambda: _reconnect_versuch(ziel_ip))
            return
        try:
            msg = _nachricht_paket_bauen(text, ziel_ip, msg_id=msg_id)
            send_paket(s, msg)
            s.close()
            zeit = datetime.now().strftime("%H:%M")
            enc = CRYPTO_OK and ziel_ip in peer_pubkeys
            eintrag = {
                "msg_id": msg_id,
                "typ": "text",
                "zeit": zeit,
                "name": benutzername,
                "text": text,
                "eingehend": False,
                "encrypted": enc,
                "gruppe": False,
            }
            nachricht_speichern(ziel_ip, eintrag)
            fenster.after(
                0, lambda e=eintrag, ip=ziel_ip: nachricht_in_chat_einfuegen(ip, e)
            )
            fenster.after(0, eingabe_leeren)
        except Exception as e:
            log.error(f"Senden: {e}")
            fenster.after(
                0, lambda: status_label.config(text=f"⚠ Fehler: {e}", fg=C_DANGER)
            )
        finally:
            try:
                s.close()
            except Exception:
                pass

    threading.Thread(target=send_thread, daemon=True).start()
    return "break"


def gruppe_senden(event=None):
    text = nachricht_eingabe.get("1.0", tk.END).strip()
    if not text or not aktive_hosts:
        return "break"
    ziele = list(aktive_hosts.keys())

    def send_thread():
        erfolge, fehler = 0, 0
        for ip in ziele:
            s = _verbinden(ip, timeout=3.0)
            if not s:
                fehler += 1
                continue
            try:
                mid = str(uuid.uuid4())
                msg = _nachricht_paket_bauen(text, ip, typ="gruppe", msg_id=mid)
                send_paket(s, msg)
                s.close()
                erfolge += 1
                zeit = datetime.now().strftime("%H:%M")
                enc = CRYPTO_OK and ip in peer_pubkeys
                eintrag = {
                    "msg_id": mid,
                    "typ": "text",
                    "zeit": zeit,
                    "name": benutzername,
                    "text": f"[Gruppe] {text}",
                    "eingehend": False,
                    "encrypted": enc,
                    "gruppe": True,
                }
                nachricht_speichern(ip, eintrag)
            except Exception as e:
                log.warning(f"Gruppe senden an {ip}: {e}")
                fehler += 1
            finally:
                try:
                    s.close()
                except Exception:
                    pass

        zeit = datetime.now().strftime("%H:%M")
        eintrag_lokal = {
            "msg_id": str(uuid.uuid4()),
            "typ": "text",
            "zeit": zeit,
            "name": benutzername,
            "text": f"[Gruppe → {erfolge} Empfänger] {text}",
            "eingehend": False,
            "encrypted": False,
            "gruppe": True,
        }
        fenster.after(0, lambda e=eintrag_lokal: _eintrag_rendern(e))
        fenster.after(0, eingabe_leeren)
        fenster.after(
            0,
            lambda: status_label.config(
                text=f"✓ Gruppe: {erfolge} gesendet, {fehler} Fehler",
                fg=C_ACCENT if not fehler else C_NAME_GRP,
            ),
        )

    threading.Thread(target=send_thread, daemon=True).start()
    return "break"


def gif_senden():
    ziel_ip = aktiver_chat
    if not ziel_ip:
        status_label.config(text="⚠ Kein Ziel ausgewählt", fg=C_DANGER)
        return
    pfad = filedialog.askopenfilename(
        title="GIF auswählen",
        filetypes=[("GIF-Dateien", "*.gif"), ("Alle Dateien", "*.*")],
    )
    if not pfad:
        return

    def send_thread():
        try:
            with open(pfad, "rb") as f:
                gif_bytes = f.read()
            if len(gif_bytes) > MAX_GIF_BYTES:
                fenster.after(
                    0,
                    lambda: status_label.config(
                        text="⚠ GIF zu groß (max 2MB)", fg=C_DANGER
                    ),
                )
                return
            s = _verbinden(ziel_ip, timeout=10.0)
            if not s:
                fenster.after(
                    0,
                    lambda: status_label.config(
                        text=f"⚠ {ziel_ip} nicht erreichbar", fg=C_DANGER
                    ),
                )
                return
            msg_id = str(uuid.uuid4())
            enc = CRYPTO_OK and ziel_ip in peer_pubkeys
            if enc:
                msg = {
                    "version": VERSION,
                    "typ": "gif",
                    "name": benutzername,
                    "msg_id": msg_id,
                    "encrypted": True,
                    "payload": verschluesseln(gif_bytes, ziel_ip),
                }
            else:
                msg = {
                    "version": VERSION,
                    "typ": "gif",
                    "name": benutzername,
                    "msg_id": msg_id,
                    "encrypted": False,
                    "gif_b64": base64.b64encode(gif_bytes).decode(),
                }
            send_paket(s, msg)
            s.close()
            dateiname = gif_speichern(gif_bytes, ziel_ip)
            zeit = datetime.now().strftime("%H:%M")
            eintrag = {
                "msg_id": msg_id,
                "typ": "gif",
                "zeit": zeit,
                "name": benutzername,
                "gif_datei": dateiname,
                "eingehend": False,
                "encrypted": enc,
                "gruppe": False,
            }
            nachricht_speichern(ziel_ip, eintrag)
            fenster.after(
                0, lambda e=eintrag, ip=ziel_ip: nachricht_in_chat_einfuegen(ip, e)
            )
            fenster.after(
                0, lambda: status_label.config(text="✓ GIF gesendet!", fg=C_ACCENT)
            )
        except Exception as e:
            log.error(f"GIF senden: {e}")
            fenster.after(
                0, lambda: status_label.config(text=f"⚠ Fehler: {e}", fg=C_DANGER)
            )

    threading.Thread(target=send_thread, daemon=True).start()


# ══════════════════════════════════════════════
# NEU: Dateiübertragung senden
# ══════════════════════════════════════════════


def datei_senden():
    ziel_ip = aktiver_chat
    if not ziel_ip:
        status_label.config(text="⚠ Kein Ziel ausgewählt", fg=C_DANGER)
        return
    pfad = filedialog.askopenfilename(title="Datei auswählen")
    if not pfad:
        return

    def send_thread():
        try:
            dateiname = os.path.basename(pfad)
            with open(pfad, "rb") as f:
                datei_bytes = f.read()
            dateigroesse = len(datei_bytes)

            if dateigroesse > MAX_FILE_BYTES:
                fenster.after(
                    0,
                    lambda: status_label.config(
                        text="⚠ Datei zu groß (max 100MB)", fg=C_DANGER
                    ),
                )
                return

            # Fortschrittsanzeige starten
            fenster.after(0, lambda: fortschritt_anzeigen(dateiname, dateigroesse))

            s = _verbinden(ziel_ip, timeout=30.0)
            if not s:
                fenster.after(
                    0,
                    lambda: status_label.config(
                        text=f"⚠ {ziel_ip} nicht erreichbar", fg=C_DANGER
                    ),
                )
                fenster.after(0, fortschritt_ausblenden)
                return

            msg_id = str(uuid.uuid4())
            enc = CRYPTO_OK and ziel_ip in peer_pubkeys

            if enc:
                payload = verschluesseln(datei_bytes, ziel_ip)
                msg = {
                    "version": VERSION,
                    "typ": "datei",
                    "name": benutzername,
                    "msg_id": msg_id,
                    "dateiname": dateiname,
                    "dateigroesse": dateigroesse,
                    "encrypted": True,
                    "payload": payload,
                }
            else:
                msg = {
                    "version": VERSION,
                    "typ": "datei",
                    "name": benutzername,
                    "msg_id": msg_id,
                    "dateiname": dateiname,
                    "dateigroesse": dateigroesse,
                    "encrypted": False,
                    "datei_b64": base64.b64encode(datei_bytes).decode(),
                }

            send_paket(s, msg)
            s.close()

            zeit = datetime.now().strftime("%H:%M")
            eintrag = {
                "msg_id": msg_id,
                "typ": "datei",
                "zeit": zeit,
                "name": benutzername,
                "dateiname": dateiname,
                "datei_pfad": pfad,
                "dateigroesse": dateigroesse,
                "eingehend": False,
                "encrypted": enc,
                "gruppe": False,
            }
            nachricht_speichern(ziel_ip, eintrag)
            fenster.after(
                0, lambda e=eintrag, ip=ziel_ip: nachricht_in_chat_einfuegen(ip, e)
            )
            fenster.after(0, fortschritt_ausblenden)
            fenster.after(
                0,
                lambda: status_label.config(
                    text=f"✓ {dateiname} gesendet!", fg=C_ACCENT
                ),
            )
        except Exception as e:
            log.error(f"Datei senden: {e}")
            fenster.after(
                0, lambda: status_label.config(text=f"⚠ Fehler: {e}", fg=C_DANGER)
            )
            fenster.after(0, fortschritt_ausblenden)

    threading.Thread(target=send_thread, daemon=True).start()


def _reconnect_versuch(ip: str):
    def check():
        s = _verbinden(ip, timeout=2.0)
        if s:
            s.close()
            fenster.after(0, aktualisiere_dropdown)
            fenster.after(
                0,
                lambda: status_label.config(
                    text=f"● Verbindung zu {ip} wiederhergestellt", fg=C_ACCENT
                ),
            )
        else:
            with _hosts_lock:
                aktive_hosts.pop(ip, None)
            fenster.after(0, aktualisiere_dropdown)

    threading.Thread(target=check, daemon=True).start()


def eingabe_leeren():
    nachricht_eingabe.delete("1.0", tk.END)
    nachricht_eingabe.config(height=3)


# ══════════════════════════════════════════════
# NEU: Nachricht löschen / bearbeiten
# ══════════════════════════════════════════════


def nachricht_loeschen_senden(msg_id: str, ziel_ip: str):
    """Schickt Lösch-Signal an Peer und aktualisiert lokal."""

    def sende():
        s = _verbinden(ziel_ip, timeout=3.0)
        if s:
            send_paket(s, {"version": VERSION, "typ": "loeschen", "msg_id": msg_id})
            s.close()

    threading.Thread(target=sende, daemon=True).start()
    eintrag_aktualisieren(
        ziel_ip, msg_id, {"text": "[Nachricht gelöscht]", "geloescht": True}
    )
    chat_eintrag_ui_aktualisieren(msg_id, "[Nachricht gelöscht]", geloescht=True)


def nachricht_bearbeiten_dialog(msg_id: str, alter_text: str, ziel_ip: str):
    """Öffnet Dialog zum Bearbeiten und sendet dann Update."""
    neuer_text = simpledialog.askstring(
        "Nachricht bearbeiten", "Neuer Text:", initialvalue=alter_text, parent=fenster
    )
    if not neuer_text or neuer_text.strip() == alter_text:
        return
    neuer_text = neuer_text.strip()

    def sende():
        s = _verbinden(ziel_ip, timeout=3.0)
        if s:
            send_paket(
                s,
                {
                    "version": VERSION,
                    "typ": "bearbeiten",
                    "msg_id": msg_id,
                    "text": neuer_text,
                },
            )
            s.close()

    threading.Thread(target=sende, daemon=True).start()
    eintrag_aktualisieren(ziel_ip, msg_id, {"text": neuer_text, "bearbeitet": True})
    chat_eintrag_ui_aktualisieren(msg_id, neuer_text, bearbeitet=True)


def chat_eintrag_ui_aktualisieren(
    msg_id: str, neuer_text: str, geloescht=False, bearbeitet=False
):
    """Aktualisiert Text-Label einer Nachricht im Chat-Widget."""
    lbl = msg_widgets.get(f"text_{msg_id}")
    if not lbl:
        return
    suffix = ""
    if geloescht:
        suffix = ""
        lbl.config(
            text=f"  {neuer_text}", fg=C_TEXT_DIM, font=("Segoe UI", 10, "italic")
        )
    elif bearbeitet:
        suffix = " (bearbeitet)"
        lbl.config(text=f"  {neuer_text}{suffix}")


def kontextmenu_anzeigen(event, msg_id: str, text: str, ziel_ip: str):
    """Rechtsklick-Menü für eigene Nachrichten."""
    menu = tk.Menu(
        fenster,
        tearoff=0,
        bg=C_INPUT,
        fg=C_TEXT,
        activebackground=C_ACCENT,
        activeforeground="white",
        font=("Segoe UI", 10),
    )
    menu.add_command(
        label="✏  Bearbeiten",
        command=lambda: nachricht_bearbeiten_dialog(msg_id, text, ziel_ip),
    )
    menu.add_command(
        label="🗑  Löschen", command=lambda: nachricht_loeschen_senden(msg_id, ziel_ip)
    )
    try:
        menu.tk_popup(event.x_root, event.y_root)
    finally:
        menu.grab_release()


# ══════════════════════════════════════════════
# Verlauf löschen
# ══════════════════════════════════════════════


def verlauf_loeschen():
    if not aktiver_chat:
        return
    import tkinter.messagebox as mb

    if mb.askyesno(
        "Verlauf löschen",
        f"Verlauf mit {aktive_hosts.get(aktiver_chat, aktiver_chat)} wirklich löschen?",
    ):
        chat_verlaeufe.pop(aktiver_chat, None)
        verlauf_speichern()
        chat_verlauf.config(state="normal")
        chat_verlauf.delete("1.0", tk.END)
        chat_verlauf.config(state="disabled")
        status_label.config(text="Verlauf gelöscht.", fg=C_TEXT_DIM)


# ══════════════════════════════════════════════
# Emoji-Picker
# ══════════════════════════════════════════════

EMOJIS = [
    "😀",
    "😂",
    "😍",
    "🥹",
    "😎",
    "😭",
    "😤",
    "🤔",
    "😴",
    "🤯",
    "👍",
    "👎",
    "👏",
    "🙌",
    "🤝",
    "🫡",
    "✌️",
    "🤙",
    "💪",
    "🖕",
    "❤️",
    "🔥",
    "💯",
    "✅",
    "❌",
    "⚠️",
    "🎉",
    "🎮",
    "💀",
    "👻",
    "🐶",
    "🐱",
    "🐻",
    "🦊",
    "🐼",
    "🐸",
    "🦁",
    "🐺",
    "🐧",
    "🦅",
    "🍕",
    "🍔",
    "🍟",
    "🌮",
    "🍺",
    "☕",
    "🍩",
    "🍦",
    "🥩",
    "🎂",
]
emoji_fenster_ref = [None]


def emoji_picker_oeffnen():
    if emoji_fenster_ref[0] and tk.Toplevel.winfo_exists(emoji_fenster_ref[0]):
        emoji_fenster_ref[0].destroy()
        emoji_fenster_ref[0] = None
        return
    picker = tk.Toplevel(fenster)
    picker.title("Emojis")
    picker.configure(bg=C_PANEL)
    picker.resizable(False, False)
    emoji_fenster_ref[0] = picker
    picker.update_idletasks()
    picker.geometry(
        f"340x200+{fenster.winfo_x()+30}+{fenster.winfo_y()+fenster.winfo_height()-260}"
    )
    frame = tk.Frame(picker, bg=C_PANEL)
    frame.pack(padx=8, pady=8)
    for i, emoji in enumerate(EMOJIS):
        tk.Button(
            frame,
            text=emoji,
            font=("Segoe UI Emoji", 16),
            bg=C_INPUT,
            fg=C_TEXT,
            relief="flat",
            bd=0,
            width=2,
            cursor="hand2",
            command=lambda e=emoji: emoji_einfuegen(e),
        ).grid(row=i // 10, column=i % 10, padx=2, pady=2)


def emoji_einfuegen(emoji: str):
    nachricht_eingabe.insert(tk.INSERT, emoji)
    nachricht_eingabe.focus()


# ══════════════════════════════════════════════
# Chat-Anzeige
# ══════════════════════════════════════════════


def nachricht_in_chat_einfuegen(ip: str, eintrag: dict):
    global aktiver_chat
    if aktiver_chat is None:
        chat_wechseln(ip)
        return
    if ip != aktiver_chat:
        if ip in aktive_hosts:
            aktualisiere_dropdown(ungelesen=ip)
        return
    _eintrag_rendern(eintrag)


def _eintrag_rendern(eintrag: dict):
    chat_verlauf.config(state="normal")
    eingehend = eintrag.get("eingehend", True)
    ist_gruppe = eintrag.get("gruppe", False)
    msg_id = eintrag.get("msg_id", "")
    geloescht = eintrag.get("geloescht", False)
    bearbeitet = eintrag.get("bearbeitet", False)

    name_tag = (
        "gruppe_name"
        if ist_gruppe
        else ("eingehend_name" if eingehend else "ausgehend_name")
    )
    name_text = eintrag.get("name", "?") if eingehend else "Du"
    lock_icon = " 🔒" if eintrag.get("encrypted") else " 🔓"
    gruppe_icon = " 👥" if ist_gruppe else ""

    chat_verlauf.insert(
        tk.END,
        f"[{eintrag['zeit']}] {name_text}{gruppe_icon}{lock_icon}\n",
        name_tag,
    )

    if eintrag.get("typ") == "gif":
        gif_bytes = gif_bytes_laden(eintrag.get("gif_datei", ""))
        container = tk.Frame(chat_verlauf, bg=C_BG)
        if gif_bytes:
            gif_einfuegen(container, gif_bytes)
        else:
            tk.Label(container, text="[GIF nicht gefunden]", bg=C_BG, fg=C_DANGER).pack(
                anchor="w"
            )
        chat_verlauf.window_create(tk.END, window=container)
        chat_verlauf.insert(tk.END, "\n\n")

    elif eintrag.get("typ") == "datei":
        # ── Datei-Bubble ──
        container = tk.Frame(
            chat_verlauf, bg=C_BUBBLE_IN if eingehend else C_BUBBLE_OUT, padx=8, pady=4
        )
        dateiname = eintrag.get("dateiname", "Datei")
        dateigroesse = eintrag.get("dateigroesse", 0)
        groesse_text = _groesse_formatieren(dateigroesse)
        datei_pfad = eintrag.get("datei_pfad", "")

        tk.Label(
            container,
            text=f"📎 {dateiname}",
            font=("Segoe UI", 10, "bold"),
            bg=container["bg"],
            fg=C_TEXT,
        ).pack(anchor="w")
        tk.Label(
            container,
            text=groesse_text,
            font=("Segoe UI", 8),
            bg=container["bg"],
            fg=C_TEXT_DIM,
        ).pack(anchor="w")

        if eingehend and datei_pfad and os.path.exists(datei_pfad):
            tk.Button(
                container,
                text="📂 Ordner öffnen",
                font=("Segoe UI", 9),
                bg=C_INPUT,
                fg=C_TEXT,
                relief="flat",
                bd=0,
                cursor="hand2",
                command=lambda p=datei_pfad: ordner_oeffnen(p),
            ).pack(anchor="w", pady=(4, 0))

        chat_verlauf.window_create(tk.END, window=container)
        chat_verlauf.insert(tk.END, "\n\n")

    else:
        # ── Text-Bubble ──
        text_tag = "eingehend_text" if eingehend else "ausgehend_text"
        raw_text = eintrag.get("text", "")

        if geloescht:
            raw_text = "[Nachricht gelöscht]"
            text_tag = "geloescht_text"
        elif bearbeitet:
            raw_text = raw_text + " (bearbeitet)"

        # Text als Label einbetten damit wir es später ändern können
        container = tk.Frame(chat_verlauf, bg=C_BG)
        text_lbl = tk.Label(
            container,
            text=f"  {raw_text}",
            font=("Segoe UI", 10),
            bg=C_BG,
            fg=C_TEXT_DIM if geloescht else C_TEXT,
            wraplength=380,
            justify="left",
            anchor="w",
        )
        text_lbl.pack(side="left", fill="x", expand=True)

        # Receipt-Label nur für ausgehende Nachrichten
        if not eingehend and msg_id:
            receipt_lbl = tk.Label(
                container, text=" ✓", font=("Segoe UI", 9), bg=C_BG, fg=C_TEXT_DIM
            )
            receipt_lbl.pack(side="right", anchor="e")
            msg_widgets[msg_id] = receipt_lbl

        # Text-Label für spätere Aktualisierungen merken
        if msg_id:
            msg_widgets[f"text_{msg_id}"] = text_lbl

        # Rechtsklick nur auf eigene, nicht gelöschte Nachrichten
        if not eingehend and not geloescht and msg_id and aktiver_chat:
            text_lbl.bind(
                "<Button-3>",
                lambda e, mid=msg_id, t=eintrag.get(
                    "text", ""
                ), ip=aktiver_chat: kontextmenu_anzeigen(e, mid, t, ip),
            )
            text_lbl.config(cursor="hand2")

        chat_verlauf.window_create(tk.END, window=container)
        chat_verlauf.insert(tk.END, "\n\n")

    chat_verlauf.config(state="disabled")
    chat_verlauf.see(tk.END)
    if not eingehend:
        status_label.config(text="✓ Gesendet!", fg=C_ACCENT)


def _groesse_formatieren(byte_anzahl: int) -> str:
    if byte_anzahl < 1024:
        return f"{byte_anzahl} B"
    elif byte_anzahl < 1024**2:
        return f"{byte_anzahl / 1024:.1f} KB"
    elif byte_anzahl < 1024**3:
        return f"{byte_anzahl / 1024**2:.1f} MB"
    return f"{byte_anzahl / 1024**3:.1f} GB"


def ordner_oeffnen(pfad: str):
    """Öffnet den Dateiordner im Explorer/Finder."""
    ordner = os.path.dirname(pfad)
    if os.name == "nt":
        os.startfile(ordner)
    elif os.uname().sysname == "Darwin":
        os.system(f'open "{ordner}"')
    else:
        os.system(f'xdg-open "{ordner}"')


def chat_wechseln(ip: str):
    global aktiver_chat
    aktiver_chat = ip
    name = aktive_hosts.get(ip, ip)
    enc_status = " 🔒" if (CRYPTO_OK and ip in peer_pubkeys) else " 🔓"
    fenster.title(f"Messenger  —  {name} ({ip}){enc_status}  v{VERSION}")
    tipp_label.config(text="")
    online_label.config(text=online_status_text(ip))
    laufende_animationen.clear()
    # Widget-Referenzen leeren beim Chat-Wechsel
    msg_widgets.clear()
    chat_verlauf.config(state="normal")
    chat_verlauf.delete("1.0", tk.END)
    for eintrag in chat_verlaeufe.get(ip, []):
        _eintrag_rendern(eintrag)
    chat_verlauf.config(state="disabled")
    chat_verlauf.see(tk.END)
    aktualisiere_dropdown()
    ungelesene.discard(ip)


# ══════════════════════════════════════════════
# Fortschrittsbalken (Dateiübertragung)
# ══════════════════════════════════════════════

_fortschritt_fenster = [None]


def fortschritt_anzeigen(dateiname: str, groesse: int):
    if _fortschritt_fenster[0]:
        return
    fw = tk.Toplevel(fenster)
    fw.title("Sende Datei...")
    fw.configure(bg=C_PANEL)
    fw.resizable(False, False)
    fw.geometry(f"320x90+{fenster.winfo_x()+90}+{fenster.winfo_y()+300}")
    fw.attributes("-topmost", True)
    _fortschritt_fenster[0] = fw
    tk.Label(
        fw,
        text=f"📤 {dateiname[:40]}",
        font=("Segoe UI", 10, "bold"),
        bg=C_PANEL,
        fg=C_TEXT,
    ).pack(padx=16, pady=(12, 4), anchor="w")
    tk.Label(
        fw,
        text=f"Größe: {_groesse_formatieren(groesse)}",
        font=("Segoe UI", 9),
        bg=C_PANEL,
        fg=C_TEXT_DIM,
    ).pack(padx=16, anchor="w")
    pb = ttk.Progressbar(fw, mode="indeterminate", length=280)
    pb.pack(padx=16, pady=8)
    pb.start(12)


def fortschritt_ausblenden():
    fw = _fortschritt_fenster[0]
    if fw:
        try:
            fw.destroy()
        except Exception:
            pass
        _fortschritt_fenster[0] = None


# ══════════════════════════════════════════════
# Dropdown & Status
# ══════════════════════════════════════════════


def aktualisiere_dropdown(ungelesen: str | None = None):
    if ungelesen:
        ungelesene.add(ungelesen)
    fenster.after(0, _update_dropdown_main_thread)


def _update_dropdown_main_thread():
    menu = ziel_dropdown["menu"]
    menu.delete(0, "end")
    with _hosts_lock:
        hosts_snapshot = dict(aktive_hosts)
    if not hosts_snapshot:
        menu.add_command(label="Keine aktiven Hosts", command=lambda: None)
        ziel_var.set("Keine aktiven Hosts")
        status_label.config(text="Scanne Netzwerk...", fg=C_TEXT_DIM)
        return
    for ip, name in hosts_snapshot.items():
        marker = "🔴 " if ip in ungelesene else "● "
        enc = "🔒" if (CRYPTO_OK and ip in peer_pubkeys) else "🔓"
        status = " 🟢" if (time.time() - letzter_kontakt.get(ip, 0)) < 60 else ""
        menu.add_command(
            label=f"{marker}{name} {enc}{status}  ({ip})",
            command=lambda i=ip: chat_wechseln(i),
        )
    if aktiver_chat and aktiver_chat in hosts_snapshot:
        ungelesene.discard(aktiver_chat)
        name = hosts_snapshot[aktiver_chat]
        enc = "🔒" if (CRYPTO_OK and aktiver_chat in peer_pubkeys) else "🔓"
        ziel_var.set(f"● {name} {enc}  ({aktiver_chat})")
    elif hosts_snapshot:
        fenster.after(0, lambda: chat_wechseln(list(hosts_snapshot.keys())[0]))
    status_label.config(text=f"● {len(hosts_snapshot)} Host(s) aktiv", fg=C_ACCENT)


def anpassen(event=None):
    zeilen = int(nachricht_eingabe.index("end-1c").split(".")[0])
    nachricht_eingabe.config(height=max(1, min(zeilen, 6)))


# ══════════════════════════════════════════════
# Name ändern
# ══════════════════════════════════════════════


def name_aendern():
    global benutzername
    neuer = simpledialog.askstring(
        "Name ändern", "Neuer Benutzername:", initialvalue=benutzername, parent=fenster
    )
    if neuer and neuer.strip():
        benutzername = neuer.strip()
        config_speichern({"benutzername": benutzername})
        fenster.title(f"Messenger  —  {benutzername}  ({eigene_ip})  v{VERSION}")
        info_label.config(text=_info_text())
        status_label.config(text=f"Name geändert zu: {benutzername}", fg=C_ACCENT)


def _info_text():
    enc = "🔒 Verschlüsselt" if CRYPTO_OK else "🔓 Unverschlüsselt"
    return f"Du: {benutzername}  |  {eigene_ip}  |  v{VERSION}  |  {enc}"


# ══════════════════════════════════════════════
# Start
# ══════════════════════════════════════════════

fehlende = []
if not PILLOW_OK:
    fehlende.append("Pillow  →  pip install Pillow")
if not CRYPTO_OK:
    fehlende.append("cryptography  →  pip install cryptography")
if fehlende:
    import tkinter.messagebox as mb

    _r = tk.Tk()
    _r.withdraw()
    mb.showwarning(
        "Pakete fehlen", "Folgende Pakete fehlen:\n\n" + "\n".join(fehlende), parent=_r
    )
    _r.destroy()

verlauf_laden()
_cfg = config_laden()
_gespeicherter_name = _cfg.get("benutzername", "")

root_temp = tk.Tk()
root_temp.withdraw()
benutzername = (
    simpledialog.askstring(
        "Name", "Dein Benutzername:", initialvalue=_gespeicherter_name, parent=root_temp
    )
    or _gespeicherter_name
    or "Unbekannt"
)
root_temp.destroy()
config_speichern({"benutzername": benutzername})

# ════════════════════════════════════════════════
# Farben & Stil
# ════════════════════════════════════════════════
C_BG = "#111B21"
C_PANEL = "#1F2C34"
C_INPUT = "#2A3942"
C_BUBBLE_OUT = "#005C4B"
C_BUBBLE_IN = "#1F2C34"
C_BUBBLE_GRP = "#2D3B28"
C_TEXT = "#E9EDEF"
C_TEXT_DIM = "#8696A0"
C_ACCENT = "#00A884"
C_ACCENT2 = "#8696A0"
C_DANGER = "#EA5455"
C_NAME_IN = "#53BDEB"
C_NAME_OUT = "#00A884"
C_NAME_GRP = "#FFD279"

BTN_FONT = ("Segoe UI", 10, "bold")
BTN_PADY = 6
BTN_PADX = 14


def icon_btn(parent, text, cmd, bg=C_INPUT, fg=C_TEXT, width=None):
    kw = dict(
        text=text,
        command=cmd,
        font=BTN_FONT,
        bg=bg,
        fg=fg,
        relief="flat",
        bd=0,
        padx=BTN_PADX,
        pady=BTN_PADY,
        cursor="hand2",
        activebackground=bg,
        activeforeground=fg,
    )
    if width:
        kw["width"] = width
    return tk.Button(parent, **kw)


# ── Hauptfenster ──
fenster = tk.Tk()
fenster.title(f"Messenger  —  {benutzername}  ({eigene_ip})  v{VERSION}")
fenster.geometry("500x720")
fenster.minsize(420, 500)
fenster.configure(bg=C_BG)
fenster.resizable(True, True)
fenster.grid_rowconfigure(3, weight=1)
fenster.grid_columnconfigure(0, weight=1)

# ════════════════
# HEADER
# ════════════════
header = tk.Frame(fenster, bg=C_PANEL, pady=10)
header.grid(row=0, column=0, sticky="ew")
header.grid_columnconfigure(1, weight=1)

avatar_canvas = tk.Canvas(header, width=38, height=38, bg=C_PANEL, highlightthickness=0)
avatar_canvas.grid(row=0, column=0, rowspan=2, padx=(16, 10), pady=2)
avatar_canvas.create_oval(2, 2, 36, 36, fill=C_ACCENT, outline="")
avatar_canvas.create_text(
    19, 19, text=benutzername[:1].upper(), font=("Segoe UI", 14, "bold"), fill="white"
)

tk.Label(
    header,
    text=benutzername,
    font=("Segoe UI", 12, "bold"),
    bg=C_PANEL,
    fg=C_TEXT,
    anchor="w",
).grid(row=0, column=1, sticky="w")
info_label = tk.Label(
    header,
    text=_info_text(),
    font=("Segoe UI", 8),
    bg=C_PANEL,
    fg=C_TEXT_DIM,
    anchor="w",
)
info_label.grid(row=1, column=1, sticky="w")

hbtn = tk.Frame(header, bg=C_PANEL)
hbtn.grid(row=0, column=2, rowspan=2, padx=(0, 12))
icon_btn(hbtn, "✏", name_aendern, bg=C_INPUT, fg=C_TEXT).pack(side="left", padx=3)
icon_btn(hbtn, "🗑", verlauf_loeschen, bg=C_INPUT, fg=C_DANGER).pack(side="left", padx=3)

# ════════════════
# CHAT-KOPF
# ════════════════
chat_kopf = tk.Frame(fenster, bg=C_PANEL, pady=6)
chat_kopf.grid(row=1, column=0, sticky="ew")
chat_kopf.grid_columnconfigure(0, weight=1)

ziel_frame = tk.Frame(chat_kopf, bg=C_PANEL)
ziel_frame.grid(row=0, column=0, sticky="ew", padx=16)
ziel_frame.grid_columnconfigure(1, weight=1)

tk.Label(ziel_frame, text="An:", font=("Segoe UI", 9), bg=C_PANEL, fg=C_TEXT_DIM).grid(
    row=0, column=0, padx=(0, 8)
)
ziel_var = tk.StringVar(value="Scanne Netzwerk...")
ziel_dropdown = tk.OptionMenu(ziel_frame, ziel_var, "Scanne...")
ziel_dropdown.config(
    font=("Segoe UI", 10),
    bg=C_INPUT,
    fg=C_TEXT,
    activebackground=C_ACCENT,
    activeforeground="white",
    relief="flat",
    bd=0,
    highlightthickness=0,
    anchor="w",
)
ziel_dropdown["menu"].config(
    bg=C_INPUT,
    fg=C_TEXT,
    font=("Segoe UI", 10),
    activebackground=C_ACCENT,
    activeforeground="white",
)
ziel_dropdown.grid(row=0, column=1, sticky="ew")

# ── NEU: Online-Status Label ──
online_label = tk.Label(
    chat_kopf, text="", font=("Segoe UI", 8), bg=C_PANEL, fg=C_ACCENT, anchor="w"
)
online_label.grid(row=1, column=0, sticky="w", padx=16)

tipp_label = tk.Label(
    chat_kopf, text="", font=("Segoe UI", 8, "italic"), bg=C_PANEL, fg=C_ACCENT
)
tipp_label.grid(row=2, column=0, sticky="w", padx=16)

tk.Frame(fenster, bg="#2A3942", height=1).grid(row=2, column=0, sticky="ew")

# ════════════════
# CHAT-VERLAUF
# ════════════════
chat_verlauf = scrolledtext.ScrolledText(
    fenster,
    font=("Segoe UI", 10),
    bg=C_BG,
    fg=C_TEXT,
    relief="flat",
    bd=0,
    state="disabled",
    wrap="word",
    padx=12,
    pady=10,
    spacing3=4,
)
chat_verlauf.grid(row=3, column=0, sticky="nsew")
chat_verlauf.tag_config(
    "eingehend_name", foreground=C_NAME_IN, font=("Segoe UI", 9, "bold")
)
chat_verlauf.tag_config("eingehend_text", foreground=C_TEXT, lmargin1=12, lmargin2=12)
chat_verlauf.tag_config(
    "ausgehend_name", foreground=C_NAME_OUT, font=("Segoe UI", 9, "bold")
)
chat_verlauf.tag_config("ausgehend_text", foreground=C_TEXT, lmargin1=12, lmargin2=12)
chat_verlauf.tag_config(
    "gruppe_name", foreground=C_NAME_GRP, font=("Segoe UI", 9, "bold")
)
chat_verlauf.tag_config(
    "geloescht_text",
    foreground=C_TEXT_DIM,
    font=("Segoe UI", 10, "italic"),
    lmargin1=12,
    lmargin2=12,
)
chat_verlauf.tag_config("zeitstempel", foreground=C_TEXT_DIM, font=("Segoe UI", 7))

tk.Frame(fenster, bg="#2A3942", height=1).grid(row=4, column=0, sticky="ew")

# ════════════════
# FOOTER
# ════════════════
footer = tk.Frame(fenster, bg=C_PANEL, pady=10)
footer.grid(row=5, column=0, sticky="ew")
footer.grid_columnconfigure(1, weight=1)

links = tk.Frame(footer, bg=C_PANEL)
links.grid(row=0, column=0, padx=(12, 6))
icon_btn(links, "😀", emoji_picker_oeffnen, bg=C_PANEL, fg=C_TEXT_DIM).pack(side="left")
icon_btn(links, "GIF", gif_senden, bg=C_PANEL, fg=C_TEXT_DIM).pack(
    side="left", padx=(4, 0)
)
icon_btn(links, "📎", datei_senden, bg=C_PANEL, fg=C_TEXT_DIM).pack(
    side="left", padx=(4, 0)
)  # NEU
icon_btn(links, "👥", gruppe_senden, bg=C_PANEL, fg=C_TEXT_DIM).pack(
    side="left", padx=(4, 0)
)

eingabe_frame = tk.Frame(footer, bg=C_INPUT, pady=4, padx=8)
eingabe_frame.grid(row=0, column=1, sticky="ew", padx=(0, 8))
nachricht_eingabe = tk.Text(
    eingabe_frame,
    height=1,
    font=("Segoe UI", 11),
    bg=C_INPUT,
    fg=C_TEXT,
    insertbackground=C_TEXT,
    relief="flat",
    bd=0,
    wrap="word",
)
nachricht_eingabe.pack(fill="both", expand=True)

icon_btn(footer, "➤", senden, bg=C_ACCENT, fg="white", width=3).grid(
    row=0, column=2, padx=(0, 12)
)

status_label = tk.Label(
    fenster,
    text="Scanne Netzwerk...",
    font=("Segoe UI", 8),
    bg=C_BG,
    fg=C_TEXT_DIM,
    anchor="w",
)
status_label.grid(row=6, column=0, sticky="ew", padx=16, pady=(2, 6))

# Bindings
nachricht_eingabe.bind(
    "<KeyRelease>",
    lambda e: (anpassen(e), tipp_signal_senden(e), tipp_reset_starten(e)),
)
nachricht_eingabe.bind("<Return>", senden)
nachricht_eingabe.bind(
    "<Control-Return>", lambda e: nachricht_eingabe.insert(tk.INSERT, "\n") or "break"
)

# ── Start ──
threading.Thread(target=server_starten, daemon=True).start()
threading.Thread(target=scan_netz, daemon=True).start()
fenster.after(30_000, online_status_aktualisieren)  # Online-Status-Timer starten

# Update-Check beim Start (läuft im Hintergrund, blockiert nicht)
fenster.after(2000, lambda: update_pruefen(VERSION, fenster))

fenster.mainloop()
