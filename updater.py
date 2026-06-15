"""
updater.py  –  Messenger Auto-Updater
======================================
Wird beim Start vom Messenger aufgerufen.
Prüft GitHub Releases auf eine neuere Version und bietet Update an.

WIE DU DAS BENUTZT:
1. Erstelle ein GitHub Repo (z.B. "messenger")
2. Ändere GITHUB_USER und GITHUB_REPO unten
3. Wenn du eine neue Version veröffentlichst:
   a) VERSION in messenger.py erhöhen (z.B. 5 → 6)
   b) PyInstaller: pyinstaller --onefile --windowed --name messenger messenger_v5.py
   c) GitHub → Releases → "Create new release"
   d) Tag: v6  |  Title: Version 6  |  .exe hochladen → "Publish release"
   e) Fertig – alle Clients kriegen beim nächsten Start den Hinweis
"""

import urllib.request
import urllib.error
import json
import os
import sys
import subprocess
import tempfile
import threading
import tkinter as tk
from tkinter import messagebox

# ══════════════════════════════════════════════
# GitHub Konfiguration
# ══════════════════════════════════════════════
GITHUB_USER = "Ap0calyps92"
GITHUB_REPO = "Lan-Messenger"
# ══════════════════════════════════════════════

RELEASES_API = (
    f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/releases/latest"
)
TIMEOUT = 5  # Sekunden für den API-Request


def _get_latest_release() -> dict | None:
    """Fragt die GitHub API nach dem neuesten Release."""
    try:
        req = urllib.request.Request(
            RELEASES_API,
            headers={"User-Agent": "messenger-updater/1.0"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _versionsnummer(tag: str) -> int:
    """
    Wandelt einen GitHub-Tag in eine Ganzzahl um.
    "v6" → 6 | "v5.1" → 51 | "6" → 6
    Gibt 0 zurück wenn Parsing fehlschlägt.
    """
    tag = tag.lstrip("v").replace(".", "")
    try:
        return int(tag)
    except ValueError:
        return 0


def _exe_asset_url(release: dict) -> str | None:
    """Sucht in den Release-Assets nach einer .exe Datei."""
    for asset in release.get("assets", []):
        if asset.get("name", "").endswith(".exe"):
            return asset.get("browser_download_url")
    return None


def _download_und_ersetzen(download_url: str, changelog: str, neue_version: int):
    """
    Lädt die neue .exe herunter, ersetzt die aktuelle und startet neu.
    Läuft im Hintergrund-Thread, zeigt Fortschritt im Status-Fenster.
    """
    # ── Fortschritts-Popup ──
    popup = tk.Toplevel()
    popup.title("Update wird installiert...")
    popup.resizable(False, False)
    popup.attributes("-topmost", True)
    popup.geometry("360x100")
    popup.configure(bg="#1F2C34")

    status_var = tk.StringVar(value="Verbinde mit Server...")
    tk.Label(
        popup,
        textvariable=status_var,
        font=("Segoe UI", 10),
        bg="#1F2C34",
        fg="#E9EDEF",
    ).pack(pady=(18, 6), padx=20)

    fortschritt_var = tk.StringVar(value="")
    tk.Label(
        popup,
        textvariable=fortschritt_var,
        font=("Segoe UI", 8),
        bg="#1F2C34",
        fg="#8696A0",
    ).pack()

    def aktualisiere(text: str, detail: str = ""):
        status_var.set(text)
        fortschritt_var.set(detail)
        popup.update()

    def download_thread():
        try:
            # Zieldatei = aktuell laufende .exe
            eigene_exe = sys.executable if getattr(sys, "frozen", False) else __file__

            # Temporäre Datei im selben Ordner
            ziel_ordner = os.path.dirname(os.path.abspath(eigene_exe))
            tmp_fd, tmp_pfad = tempfile.mkstemp(suffix=".exe", dir=ziel_ordner)
            os.close(tmp_fd)

            # Download mit Fortschrittsanzeige
            aktualisiere("Lade Update herunter...", download_url.split("/")[-1])

            def fortschritt_callback(block_num, block_size, total_size):
                if total_size > 0:
                    prozent = min(100, block_num * block_size * 100 // total_size)
                    mb_geladen = block_num * block_size / 1024 / 1024
                    mb_gesamt = total_size / 1024 / 1024
                    aktualisiere(
                        f"Lade Update herunter... {prozent}%",
                        f"{mb_geladen:.1f} MB / {mb_gesamt:.1f} MB",
                    )

            urllib.request.urlretrieve(download_url, tmp_pfad, fortschritt_callback)
            aktualisiere("Installiere Update...")

            # Batch-Script: wartet bis Messenger geschlossen, ersetzt .exe, startet neu
            # (Nötig weil Windows eine laufende .exe nicht überschreiben lässt)
            if os.name == "nt":
                batch_inhalt = f"""@echo off
ping 127.0.0.1 -n 3 > nul
move /Y "{tmp_pfad}" "{eigene_exe}"
start "" "{eigene_exe}"
del "%~f0"
"""
                batch_fd, batch_pfad = tempfile.mkstemp(suffix=".bat", dir=ziel_ordner)
                with os.fdopen(batch_fd, "w") as f:
                    f.write(batch_inhalt)

                subprocess.Popen(
                    ["cmd.exe", "/c", batch_pfad],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            else:
                # Linux/Mac: direkt ersetzen
                os.replace(tmp_pfad, eigene_exe)
                subprocess.Popen([eigene_exe])

            aktualisiere("✓ Update installiert! Programm startet neu...")
            popup.after(1500, lambda: os._exit(0))

        except Exception as e:
            aktualisiere(f"⚠ Fehler: {e}", "Update fehlgeschlagen.")
            popup.after(3000, popup.destroy)

    threading.Thread(target=download_thread, daemon=True).start()
    popup.mainloop()


def update_pruefen(aktuelle_version: int, parent_fenster=None):
    """
    Hauptfunktion – wird beim Messenger-Start aufgerufen.

    aktuelle_version : int  – VERSION aus messenger.py
    parent_fenster   : tk.Tk – damit der Dialog zentriert erscheint

    Läuft im Hintergrund-Thread damit der Start nicht blockiert wird.
    """

    def check_thread():
        release = _get_latest_release()
        if not release:
            return  # Kein Internet oder API nicht erreichbar → still ignorieren

        tag = release.get("tag_name", "0")
        neue_version = _versionsnummer(tag)
        changelog = release.get("body", "Keine Details verfügbar.").strip()
        download_url = _exe_asset_url(release)

        if neue_version <= aktuelle_version:
            return  # Bereits aktuell

        if not download_url:
            return  # Release hat keine .exe → ignorieren

        # UI muss im Main-Thread laufen
        def zeige_dialog():
            antwort = messagebox.askyesno(
                title=f"Update verfügbar – v{neue_version}",
                message=(
                    f"Eine neue Version ist verfügbar!\n\n"
                    f"Installiert:  v{aktuelle_version}\n"
                    f"Verfügbar:   v{neue_version}\n\n"
                    f"Was ist neu:\n{changelog[:300]}{'...' if len(changelog) > 300 else ''}\n\n"
                    f"Jetzt updaten?"
                ),
                parent=parent_fenster,
            )
            if antwort:
                _download_und_ersetzen(download_url, changelog, neue_version)

        if parent_fenster:
            parent_fenster.after(0, zeige_dialog)
        else:
            zeige_dialog()

    threading.Thread(target=check_thread, daemon=True).start()
