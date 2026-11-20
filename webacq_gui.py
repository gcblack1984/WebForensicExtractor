#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Forensic Extractor - Acquisizione forense di pagine web con interfaccia grafica.
Autore: Giovanni Ciccarese

Copyright (C) 2026 Giovanni Ciccarese
Concesso in licenza a norma dell'EUPL, versione 1.2 o successive (vedi LICENZA.txt e AVVISI.txt).
SPDX-License-Identifier: EUPL-1.2

Modalità:
  - Pagina pubblica: browser pulito (nessun cookie, nessuna sessione), nessun login.
  - Con login: si sceglie la piattaforma, si effettua il login (sessione NON registrata,
    salvata in un profilo dedicato per piattaforma), poi si acquisisce.

Requisiti (sviluppo):
    pip install playwright ntplib asn1crypto
    playwright install chromium
"""

import datetime as dt
import getpass
import hashlib
import json
import os
import platform
import queue
import re
import secrets
import shutil
import socket
import sys
import threading
import urllib.request
import zipfile
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
from urllib.parse import urlparse

import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

import ttkbootstrap as ttk

FROZEN = getattr(sys, "frozen", False)
if FROZEN:
    # Chromium incluso nel pacchetto (installato con PLAYWRIGHT_BROWSERS_PATH=0)
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "0")
BASE_DIR = Path(sys.executable).parent if FROZEN else Path(__file__).resolve().parent


def resource_path(name):
    """Percorso di una risorsa inclusa nel pacchetto (splash, icona)."""
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / name


# Le librerie pesanti (Playwright, python-docx tramite verbale.py) NON vengono importate qui:
# le carica load_heavy_modules() in sottofondo, mentre lo splash mostra la barra di avanzamento.
V = None  # modulo verbale, disponibile al termine del caricamento

TOOL_NAME = "Web Forensic Extractor"
TOOL_VERSION = "4.2.0"
TOOL_AUTHOR = "Giovanni Ciccarese"
MIN_SPLASH_S = 3.0   # durata minima dello splash, in secondi
WINDOW_SIZE = (980, 800)


def _is_packaged():
    """True se il programma è installato come pacchetto MSIX (ad esempio dal Microsoft Store).
    In quel caso la cartella del programma è in sola lettura."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        length = ctypes.c_uint32(0)
        rc = ctypes.windll.kernel32.GetCurrentPackageFullName(ctypes.byref(length), None)
        return rc != 15700  # 15700 = APPMODEL_ERROR_NO_PACKAGE: programma non impacchettato
    except Exception:
        return False


def _writable(folder):
    try:
        folder.mkdir(parents=True, exist_ok=True)
        probe = folder / ".wfe_scrittura"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except Exception:
        return False


def _documents_dir():
    """Cartella Documenti dell'utente (anche se spostata, ad esempio su OneDrive)."""
    if sys.platform == "win32":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(1024)
            if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf) == 0 and buf.value:
                return Path(buf.value)  # 5 = CSIDL_PERSONAL (Documenti)
        except Exception:
            pass
    return Path.home() / "Documents"


PACKAGED = _is_packaged()
if PACKAGED or not _writable(BASE_DIR):
    # Versione Microsoft Store (o cartella del programma non scrivibile): dati nel profilo utente,
    # acquisizioni nei Documenti, così restano all'utente anche se il programma viene disinstallato
    DISTRIBUTION = "Microsoft Store (pacchetto MSIX)" if PACKAGED else "installata"
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "WebForensicExtractor"
    DEFAULT_OUT = _documents_dir() / "Web Forensic Extractor" / "Acquisizioni"
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
else:
    # Versione portabile: tutto accanto all'eseguibile, come nelle versioni precedenti
    DISTRIBUTION = "portabile"
    DATA_DIR = BASE_DIR
    DEFAULT_OUT = BASE_DIR / "acquisizioni"

PROFILE_ROOT = DATA_DIR / "profili"
SETTINGS_FILE = DATA_DIR / "impostazioni_verbale.json"
PREFS_FILE = DATA_DIR / "preferenze.json"
THEMES = {"scuro": "darkly", "chiaro": "flatly"}


class ToolTip:
    """Suggerimento al passaggio del mouse (indipendente dalla versione di ttkbootstrap)."""

    def __init__(self, widget, text, wraplength=300, delay=450):
        self.widget, self.text, self.wraplength, self.delay = widget, text, wraplength, delay
        self.tip = None
        self.job = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None):
        self._cancel()
        self.job = self.widget.after(self.delay, self._show)

    def _cancel(self):
        if self.job:
            try:
                self.widget.after_cancel(self.job)
            except Exception:
                pass
            self.job = None

    def _show(self):
        self.job = None
        if self.tip or not self.text:
            return
        try:
            c = ttk.Style().colors
            bg, fg, bd = c.inputbg, c.inputfg, c.border
        except Exception:
            bg, fg, bd = "#ffffe0", "#000000", "#999999"
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        try:
            tw.attributes("-topmost", True)
        except Exception:
            pass
        tk.Label(tw, text=self.text, justify="left", wraplength=self.wraplength,
                 background=bg, foreground=fg, font=("Segoe UI", 9), padx=9, pady=6,
                 highlightthickness=1, highlightbackground=bd, borderwidth=0).pack()
        tw.geometry(f"+{x}+{y}")

    def _hide(self, _event=None):
        self._cancel()
        if self.tip:
            try:
                self.tip.destroy()
            except Exception:
                pass
            self.tip = None


def install_context_menu(root):
    """Menu con il tasto destro (Taglia, Copia, Incolla, Seleziona tutto) per tutti i campi
    di testo del programma, comprese le finestre del verbale e dell'archivio."""
    menu = tk.Menu(root, tearoff=0)

    def is_locked(w):
        try:  # widget ttk (campi della finestra principale, verbale, archivio)
            return w.instate(["disabled"]) or w.instate(["readonly"])
        except Exception:
            try:  # widget classici (tk.Text, registro)
                return str(w.cget("state")) in ("disabled", "readonly")
            except Exception:
                return False

    def select_all(w):
        try:
            if isinstance(w, tk.Text):
                w.tag_add("sel", "1.0", "end-1c")
            else:
                w.select_range(0, "end")
                w.icursor("end")
        except Exception:
            pass

    def show(event):
        w = event.widget
        locked = is_locked(w)
        menu.delete(0, "end")
        menu.add_command(label="Taglia", command=lambda: w.event_generate("<<Cut>>"),
                         state="disabled" if locked else "normal")
        menu.add_command(label="Copia", command=lambda: w.event_generate("<<Copy>>"))
        menu.add_command(label="Incolla", command=lambda: w.event_generate("<<Paste>>"),
                         state="disabled" if locked else "normal")
        menu.add_separator()
        menu.add_command(label="Seleziona tutto", command=lambda: select_all(w))
        try:
            w.focus_set()
        except Exception:
            pass
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    for cls in ("TEntry", "Entry", "Text", "TSpinbox", "Spinbox", "TCombobox"):
        root.bind_class(cls, "<Button-3>", show, add="+")


def style_text(widget):
    """Allinea un widget tk.Text ai colori del tema attivo."""
    c = ttk.Style().colors
    widget.configure(background=c.inputbg, foreground=c.inputfg, insertbackground=c.inputfg,
                     selectbackground=c.selectbg, selectforeground=c.selectfg,
                     highlightthickness=1, highlightbackground=c.border, highlightcolor=c.primary)


def load_prefs():
    try:
        return json.loads(PREFS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"tema": "chiaro"}


def save_prefs(prefs):
    try:
        PREFS_FILE.write_text(json.dumps(prefs, indent=2), encoding="utf-8")
    except Exception:
        pass
TSA_URL = "https://freetsa.org/tsr"
VIDEO_SIZE = {"width": 1600, "height": 900}
# Finestra del browser a tutto schermo: l'area della pagina segue la dimensione della finestra
WINDOW_ARGS = ["--start-maximized"]

# Riduce la riconoscibilità del browser automatizzato (navigator.webdriver = false).
# Non modifica il contenuto delle pagine; viene registrato nel manifest.
LAUNCH_ARGS = ["--disable-blink-features=AutomationControlled"]
IGNORE_DEFAULT_ARGS = ["--enable-automation"]

# --------------------------------------------------------------------------- piattaforme
# "espandi": regex sulle etichette dei pulsanti che espandono commenti/risposte/testi.
# None = espansione automatica non disponibile per quella piattaforma.
PLATFORMS = {
    "facebook": {
        "nome": "Facebook",
        "login_url": "https://www.facebook.com/",
        "domini": ["facebook.com", "fb.com", "fb.watch"],
        "espandi": re.compile(
            r"^(?:(?:visualizza|mostra) (?:altr[ieo]|tutt[ie]|ancora|\d)"
            r"|\d+ rispost[ae]$"
            r"|(?:view|see) (?:more|all|previous|\d)"
            r"|\d+ repl(?:y|ies)$"
            r"|altro(?:\.\.\.|…)$)", re.I),
    },
    "instagram": {
        "nome": "Instagram",
        "login_url": "https://www.instagram.com/accounts/login/",
        "domini": ["instagram.com"],
        "espandi": re.compile(
            r"^(?:carica altri commenti|load more comments"
            r"|(?:visualizza|mostra) (?:altr[ie]|tutt[ie]|\d|(?:le )?risposte)"
            r"|view (?:more|all|replies|\d))", re.I),
    },
    "x": {
        "nome": "X (Twitter)",
        "login_url": "https://x.com/i/flow/login",
        "domini": ["x.com", "twitter.com"],
        "espandi": re.compile(
            r"^(?:mostra (?:altr[eio]|di più|ulteriori)|show (?:more|additional))", re.I),
    },
    "linkedin": {
        "nome": "LinkedIn",
        "login_url": "https://www.linkedin.com/login",
        "domini": ["linkedin.com"],
        "espandi": re.compile(
            r"^(?:carica (?:altri commenti|(?:le )?risposte precedenti|altre risposte)"
            r"|load (?:more comments|previous replies|more replies)"
            r"|see more|(?:…|\.\.\.) ?(?:altro|more)$"
            r"|\d+ (?:rispost[ae]|repl(?:y|ies))$)", re.I),
    },
    "tiktok": {
        "nome": "TikTok",
        "login_url": "https://www.tiktok.com/login",
        "domini": ["tiktok.com"],
        "espandi": re.compile(r"^(?:visualizza (?:\d|altr)|view (?:\d|more))", re.I),
    },
    "youtube": {
        "nome": "YouTube",
        "login_url": "https://accounts.google.com/ServiceLogin?service=youtube"
                     "&continue=https://www.youtube.com/",
        "domini": ["youtube.com", "youtu.be"],
        "espandi": re.compile(
            r"^(?:\d+ (?:rispost[ae]|repl(?:y|ies))$|altre risposte|show more replies"
            r"|mostra altr|show more$|leggi tutto|read more"
            r"|(?:…|\.\.\.) ?(?:altro|more)$)", re.I),
    },
    "reddit": {
        "nome": "Reddit",
        "login_url": "https://www.reddit.com/login/",
        "domini": ["reddit.com", "redd.it"],
        "espandi": re.compile(
            r"^(?:\d+ more repl|\d+ altr[ei] rispost|altr[ei] \d+ rispost"
            r"|view more comments|visualizza altri commenti|more replies"
            r"|load more comments)", re.I),
    },
    "altro": {
        "nome": "Altro sito (URL di login personalizzato)",
        "login_url": None,
        "domini": [],
        "espandi": None,
    },
}

# Etichette mai cliccate in automatico: alterano il contenuto o compiono azioni.
DENY_RE = re.compile(
    r"^(?:rispondi|reply|segui|follow|mi piace|like|condividi|share|iscriviti|subscribe"
    r"|segnala|report|elimina|delete|nascondi|hide|blocca|block)\b|tradu|translat", re.I)


def detect_platform(url):
    host = (urlparse(url).hostname or "").lower()
    for key, p in PLATFORMS.items():
        if any(host == d or host.endswith("." + d) for d in p["domini"]):
            return key
    return None


def profile_dir(key, login_url=None):
    if key == "altro":
        host = (urlparse(login_url or "").hostname or "sito").lower()
        return PROFILE_ROOT / ("altro_" + re.sub(r"[^a-z0-9.-]", "_", host))
    return PROFILE_ROOT / key


# =========================================================================== utilità

def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def hash_file(path):
    sha256, md5 = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def ntp_check():
    try:
        import ntplib
        r = ntplib.NTPClient().request("pool.ntp.org", version=3, timeout=5)
        return {
            "server": "pool.ntp.org",
            "offset_secondi": round(r.offset, 3),
            "ora_ntp_utc": dt.datetime.fromtimestamp(r.tx_time, dt.timezone.utc).isoformat(),
        }
    except Exception as e:
        return {"errore": str(e)}


def public_ip():
    try:
        return urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode()
    except Exception as e:
        return f"non disponibile ({e})"


def pkg_version(name):
    try:
        return version(name)
    except PackageNotFoundError:
        return "n/d"


class Logger:
    """Log con timestamp UTC al millisecondo, su file e nella finestra."""

    def __init__(self, path, emit):
        self.f = open(path, "a", encoding="utf-8")
        self.emit = emit

    def __call__(self, msg):
        line = f"{utc_now().isoformat(timespec='milliseconds')} | {msg}"
        self.f.write(line + "\n")
        self.f.flush()
        self.emit("log", line)

    def close(self):
        self.f.close()


def build_tsq(digest, nonce):
    from asn1crypto import tsp
    return tsp.TimeStampReq({
        "version": 1,
        "message_imprint": {
            "hash_algorithm": {"algorithm": "sha256"},
            "hashed_message": digest,
        },
        "nonce": nonce,
        "cert_req": True,
    }).dump()


def rfc3161_timestamp(target, log):
    """Marca temporale RFC 3161 in Python puro (asn1crypto), senza openssl."""
    from asn1crypto import tsp

    digest = bytes.fromhex(hash_file(target)[0])
    nonce = secrets.randbits(63)
    tsq_der = build_tsq(digest, nonce)
    tsq = target.with_name(target.name + ".tsq")
    tsr = target.with_name(target.name + ".tsr")
    tsq.write_bytes(tsq_der)

    req = urllib.request.Request(TSA_URL, data=tsq_der,
                                 headers={"Content-Type": "application/timestamp-query"})
    try:
        data = urllib.request.urlopen(req, timeout=30).read()
    except Exception as e:
        log(f"ERRORE richiesta marca temporale a {TSA_URL}: {e}")
        return None

    resp = tsp.TimeStampResp.load(data)
    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        log(f"ERRORE: la TSA ha risposto con stato '{status}'")
        return None
    tst = resp["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed
    if tst["message_imprint"]["hashed_message"].native != digest:
        log("ERRORE: l'impronta nella risposta TSA non corrisponde al file")
        return None
    if tst["nonce"].native != nonce:
        log("ERRORE: nonce della risposta TSA non corrispondente")
        return None

    tsr.write_bytes(data)
    log(f"Marca temporale RFC 3161 ({TSA_URL}): {tsr.name}")
    log(f"  Data/ora certificata (UTC): {tst['gen_time'].native.isoformat()}")
    log(f"  Numero di serie: {tst['serial_number'].native}")
    return tsr


# =========================================================================== browser

def control_label(el):
    txt = (el.inner_text(timeout=500) or "").strip()
    if not txt:
        txt = (el.get_attribute("aria-label", timeout=500) or "").strip()
    return " ".join(txt.split())


def expand_page(page, log, rule, max_rounds=15):
    """Clicca ripetutamente i pulsanti che espandono commenti, risposte e testi."""
    log("Espansione automatica dei contenuti avviata")
    total, rnd = 0, 0
    for rnd in range(1, max_rounds + 1):
        clicked = 0
        controls = page.locator('button, [role="button"]')
        for i in range(controls.count()):
            el = controls.nth(i)
            try:
                if not el.is_visible():
                    continue
                label = control_label(el)
            except Exception:
                continue
            if not label or len(label) > 80 or DENY_RE.search(label):
                continue
            if rule.search(label):
                try:
                    el.click(timeout=2000)
                    clicked += 1
                    log(f"  click: {label!r}")
                    page.wait_for_timeout(800)
                except Exception:
                    pass
        page.mouse.wheel(0, 4000)
        page.wait_for_timeout(1500)
        total += clicked
        if clicked == 0:
            break
    log(f"Espansione terminata: {total} click in {rnd} giri. Verifica a vista il risultato.")


def capture(ctx, n, acq_dir, log):
    if not ctx.pages:
        raise RuntimeError("nessuna scheda aperta nel browser")
    page = ctx.pages[-1]
    name = f"cattura_{n:02d}"
    url, title = page.url, page.title()
    t = utc_now().isoformat(timespec="milliseconds")
    log(f"Cattura {n:02d} | URL: {url} | Titolo: {title}")
    files = []

    def save(label, fn):
        try:
            fn()
            files.append(label)
            log(f"  salvato {label}")
        except Exception as e:
            log(f"  ERRORE su {label}: {e}")

    save(f"{name}_viewport.png",
         lambda: page.screenshot(path=str(acq_dir / f"{name}_viewport.png")))
    save(f"{name}_pagina_intera.png",
         lambda: page.screenshot(path=str(acq_dir / f"{name}_pagina_intera.png"),
                                 full_page=True))
    save(f"{name}.html",
         lambda: (acq_dir / f"{name}.html").write_text(page.content(), encoding="utf-8"))
    save(f"{name}_testo.txt",
         lambda: (acq_dir / f"{name}_testo.txt").write_text(page.inner_text("body"),
                                                            encoding="utf-8"))

    def mhtml():
        cdp = ctx.new_cdp_session(page)
        data = cdp.send("Page.captureSnapshot", {"format": "mhtml"})["data"]
        with open(acq_dir / f"{name}.mhtml", "w", encoding="utf-8", newline="") as f:
            f.write(data)
        cdp.detach()

    save(f"{name}.mhtml", mhtml)
    return {"n": n, "ora_utc": t, "url": url, "titolo": title, "file": files}


# =========================================================================== worker

class Worker(threading.Thread):
    """Esegue tutte le operazioni Playwright in un unico thread."""

    def __init__(self, ui_q):
        super().__init__(daemon=True)
        self.cmd_q = queue.Queue()
        self.ui_q = ui_q
        self.p = None
        self.browser = None   # solo modalità pubblica
        self.browser_used = None
        self.ctx = None
        self.s = None         # sessione di acquisizione in corso

    def emit(self, kind, data=None):
        self.ui_q.put((kind, data))

    def send(self, cmd, arg=None):
        self.cmd_q.put((cmd, arg))

    def run(self):
        try:
            from playwright.sync_api import sync_playwright  # già caricato durante lo splash
            with sync_playwright() as p:
                self.p = p
                self.emit("state", "idle")
                while True:
                    try:
                        cmd, arg = self.cmd_q.get(timeout=0.1)
                    except queue.Empty:
                        self._pump()
                        continue
                    if cmd == "quit":
                        self._close_ctx()
                        break
                    self.emit("state", "busy")
                    try:
                        nxt = getattr(self, "do_" + cmd)(arg)
                    except Exception as e:
                        self.emit("log", f"ERRORE ({cmd}): {e}")
                        nxt = "acquiring" if self.s else ("login" if self.ctx else "idle")
                    self.emit("state", nxt)
        except Exception as e:
            self.emit("fatal", str(e))

    def _pump(self):
        """Fa elaborare a Playwright gli eventi del browser mentre si attende un comando.
        Senza questo, dialoghi e richieste della pagina restano in sospeso e il
        browser sembra bloccato (es. verifica in due passaggi di Facebook)."""
        if not self.ctx:
            return
        try:
            pages = self.ctx.pages
            if pages:
                pages[-1].wait_for_timeout(100)
        except Exception:
            pass

    def _log(self, msg):
        if self.s:
            self.s["log"](msg)
        else:
            self.emit("log", msg)

    def _on_dialog(self, dialog):
        accept = dialog.type in ("alert", "beforeunload")
        self._log(f"Finestra di dialogo del sito ({dialog.type}): {dialog.message!r} -> "
                  f"{'accettata' if accept else 'annullata'}")
        try:
            dialog.accept() if accept else dialog.dismiss()
        except Exception:
            pass

    def _launch(self, mode, profile=None, acq_dir=None, chrome=False):
        rec = {}
        if acq_dir:
            rec = {"record_har_path": str(acq_dir / "traffico_rete.har"),
                   "record_video_dir": str(acq_dir / "video"),
                   "record_video_size": VIDEO_SIZE}
        opts = {"headless": False, "args": LAUNCH_ARGS + WINDOW_ARGS,
                "ignore_default_args": IGNORE_DEFAULT_ARGS}
        channel = "chrome" if chrome else None

        def start(ch):
            if mode == "login":
                profile.mkdir(parents=True, exist_ok=True)
                self.ctx = self.p.chromium.launch_persistent_context(
                    str(profile), channel=ch, no_viewport=True, **opts, **rec)
            else:
                self.browser = self.p.chromium.launch(channel=ch, **opts)
                self.ctx = self.browser.new_context(no_viewport=True, **rec)

        try:
            start(channel)
            self.browser_used = "Google Chrome installato" if channel else "Chromium incluso"
        except Exception as e:
            if not channel:
                raise
            self._log(f"Google Chrome non disponibile ({e}); uso Chromium incluso")
            start(None)
            self.browser_used = "Chromium incluso"

        for pg in self.ctx.pages:
            pg.on("dialog", self._on_dialog)
        self.ctx.on("page", lambda pg: pg.on("dialog", self._on_dialog))
        return self.ctx.pages[0] if self.ctx.pages else self.ctx.new_page()

    def _close_ctx(self):
        for obj in (self.ctx, self.browser):
            if obj:
                try:
                    obj.close()
                except Exception:
                    pass
        self.ctx = self.browser = None

    # ---- gestione sessioni (non registrate)
    def do_login_start(self, a):
        page = self._launch("login", profile=Path(a["profile"]), chrome=a["chrome"])
        page.goto(a["login_url"])
        self.emit("log", f"Browser: {self.browser_used}")
        self.emit("log", f"Browser aperto per il login su {a['nome']} (sessione NON registrata). "
                         "Effettua il login, poi premi 'Login completato'.")
        return "login"

    def do_login_end(self, _):
        self._close_ctx()
        self.emit("log", "Sessione salvata nel profilo dedicato alla piattaforma.")
        return "idle"

    def do_clear_session(self, a):
        prof = Path(a["profile"])
        if prof.exists():
            shutil.rmtree(prof)
            self.emit("log", f"Sessione eliminata: {prof}")
        else:
            self.emit("log", "Nessuna sessione salvata da eliminare.")
        return "idle"

    # ---- acquisizione
    def do_start(self, a):
        start = utc_now()
        case_dir = Path(a["out"]) / f"{a['case']}_{start.strftime('%Y%m%dT%H%M%SZ')}"
        acq_dir = case_dir / "acquisizione"
        acq_dir.mkdir(parents=True)
        log = Logger(acq_dir / "acquisizione.log", self.emit)
        key = a["platform"]
        rule = PLATFORMS[key]["espandi"] if key else None
        nome = PLATFORMS[key]["nome"] if key else "sito generico"
        mode_txt = ("pubblica (browser pulito, nessun cookie, nessun login)"
                    if a["mode"] == "public" else "autenticata (profilo con login)")
        self.s = {"case_dir": case_dir, "acq_dir": acq_dir, "log": log,
                  "captures": [], "n": 0, "tsa": a["tsa"], "rule": rule}

        log(f"{TOOL_NAME} {TOOL_VERSION} - avvio acquisizione")
        log(f"Caso: {a['case']} | Operatore: {a['operator']} | URL: {a['url']}")
        log(f"Modalità: {mode_txt} | Piattaforma: {nome}")
        meta = {
            "strumento": f"{TOOL_NAME} {TOOL_VERSION}",
            "distribuzione": DISTRIBUTION,
            "autore_strumento": TOOL_AUTHOR,
            "eseguibile": sys.executable if FROZEN else None,
            "caso": a["case"],
            "operatore": a["operator"],
            "url_partenza": a["url"],
            "modalita": mode_txt,
            "piattaforma": nome,
            "profilo_browser": a.get("profile"),
            "inizio_utc": start.isoformat(),
            "ora_locale_inizio": dt.datetime.now().astimezone().isoformat(),
            "sistema": {
                "os": platform.platform(),
                "hostname": socket.gethostname(),
                "utente_os": getpass.getuser(),
                "python": sys.version.split()[0],
                "playwright": pkg_version("playwright"),
            },
            "ip_pubblico": public_ip(),
            "verifica_ntp": ntp_check(),
        }
        if FROZEN:
            meta["sha256_eseguibile"] = hash_file(sys.executable)[0]
        self.s["meta"] = meta
        log(f"IP pubblico: {meta['ip_pubblico']}")
        log(f"Verifica NTP: {meta['verifica_ntp']}")

        page = self._launch(a["mode"], profile=Path(a["profile"]) if a.get("profile") else None,
                            acq_dir=acq_dir, chrome=a["chrome"])
        meta["browser"] = {"tipo": self.browser_used, "argomenti_aggiunti": LAUNCH_ARGS,
                           "argomenti_rimossi": IGNORE_DEFAULT_ARGS}
        log(f"Browser: {self.browser_used} | opzioni: {LAUNCH_ARGS}, "
            f"rimosse: {IGNORE_DEFAULT_ARGS}")
        self.ctx.on("close", lambda *_: self.emit(
            "log", "ATTENZIONE: il browser è stato chiuso."))
        meta["user_agent"] = page.evaluate("navigator.userAgent")
        log(f"User-Agent: {meta['user_agent']}")
        log(f"Navigazione verso {a['url']}")
        page.goto(a["url"], wait_until="domcontentloaded")
        try:
            dims = page.evaluate("({w: window.innerWidth, h: window.innerHeight, "
                                 "sw: screen.width, sh: screen.height, dpr: window.devicePixelRatio})")
            meta["browser"]["finestra"] = {
                "modalita": "a tutto schermo (massimizzata)",
                "area_pagina": f"{dims['w']}x{dims['h']}",
                "schermo": f"{dims['sw']}x{dims['sh']}",
                "scala": dims["dpr"]}
            log(f"Finestra del browser a tutto schermo: area della pagina {dims['w']}x{dims['h']} "
                f"pixel, schermo {dims['sw']}x{dims['sh']}, scala {dims['dpr']}")
        except Exception as e:
            log(f"ATTENZIONE: dimensioni della finestra non rilevate ({e})")

        self.emit("expand", rule is not None)
        if rule:
            log("Pronto. Espandi i contenuti (a mano o con 'Espandi commenti'), "
                "poi premi 'Acquisisci stato'.")
        else:
            log("Pronto. Espandi a mano i contenuti necessari, poi premi 'Acquisisci stato'.")
        return "acquiring"

    def do_expand(self, _):
        if not self.s["rule"]:
            raise RuntimeError("espansione non disponibile per questa piattaforma")
        if not self.ctx.pages:
            raise RuntimeError("nessuna scheda aperta nel browser")
        expand_page(self.ctx.pages[-1], self.s["log"], self.s["rule"])
        return "acquiring"

    def do_capture(self, _):
        self.s["n"] += 1
        self.s["captures"].append(
            capture(self.ctx, self.s["n"], self.s["acq_dir"], self.s["log"]))
        self.emit("captures", self.s["n"])
        return "acquiring"

    def do_finish(self, _):
        s = self.s
        log, acq_dir, case_dir, meta = s["log"], s["acq_dir"], s["case_dir"], s["meta"]
        log("Chiusura browser (finalizzazione HAR e video)")
        self._close_ctx()

        meta["fine_utc"] = utc_now().isoformat()
        meta["catture"] = s["captures"]
        log(f"Fine sessione. Catture eseguite: {len(s['captures'])}")

        entries = []
        for f in sorted(acq_dir.rglob("*")):
            if f.is_file() and f.name != "acquisizione.log":
                sha, md5 = hash_file(f)
                entries.append({"file": f.relative_to(acq_dir).as_posix(),
                                "bytes": f.stat().st_size, "sha256": sha, "md5": md5})
        meta["file"] = entries
        (acq_dir / "manifest.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        log("Manifest scritto")
        log.close()

        lines = []
        for f in sorted(acq_dir.rglob("*")):
            if f.is_file():
                lines.append(f"{hash_file(f)[0]}  {f.relative_to(acq_dir).as_posix()}")
        (acq_dir / "hash_sha256.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

        zip_path = case_dir / "acquisizione.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(acq_dir.rglob("*")):
                if f.is_file():
                    z.write(f, f.relative_to(case_dir).as_posix())

        clog = Logger(case_dir / "chiusura.log", self.emit)
        sha, md5 = hash_file(zip_path)
        (case_dir / "acquisizione.zip.sha256").write_text(f"{sha}  acquisizione.zip\n",
                                                         encoding="utf-8")
        clog(f"Pacchetto: {zip_path.name} | SHA-256: {sha} | MD5: {md5}")
        if s["tsa"]:
            rfc3161_timestamp(zip_path, clog)
        else:
            clog("Marca temporale non richiesta")
        clog.close()

        self.s = None
        self.emit("expand", False)
        self.emit("done", str(case_dir.resolve()))
        return "idle"


# =========================================================================== GUI

class App:
    def __init__(self, root):
        self.root = root
        root.title(f"{TOOL_NAME} {TOOL_VERSION} - Acquisizione forense web")
        root.minsize(820, 660)
        self.ui_q = queue.Queue()
        self.worker = Worker(self.ui_q)
        self.state = "busy"
        self.expand_ok = False
        self.last_case = ""
        self.pending_case = None  # acquisizione conclusa in attesa di archiviazione/scarto
        self.prefs = load_prefs()
        # stato della registrazione (fascia di stato, contatore, cronometro)
        self.recording = False
        self.finishing = False
        self.rec_start = None
        self.rec_elapsed = 0
        self.n_captures = 0
        self._banner_style = None
        self._last_tick = -1

        outer = ttk.Frame(root, padding=(16, 12, 16, 14))
        outer.pack(fill="both", expand=True)
        self.idle_widgets = []
        self.btn = {}

        def button(parent, key, text, style, side="left", padx=4, tip=None):
            b = ttk.Button(parent, text=text, bootstyle=style,
                           command=lambda k=key: self.on_button(k))
            b.pack(side=side, padx=padx)
            self.btn[key] = b
            if tip:
                ToolTip(b, text=tip, wraplength=300)
            return b

        # ================= intestazione
        header = ttk.Frame(outer)
        header.pack(fill="x")
        titles = ttk.Frame(header)
        titles.pack(side="left")
        ttk.Label(titles, text=TOOL_NAME, font=("Segoe UI", 18, "bold"),
                  bootstyle="primary").pack(anchor="w")
        ttk.Label(titles, text=f"Acquisizione forense di contenuti web   ·   v{TOOL_VERSION}   ·   "
                               f"{TOOL_AUTHOR}   ·   Licenza EUPL 1.2", bootstyle="secondary").pack(anchor="w")
        # pack da destra: ordine visibile  Nuova acquisizione | Verbale… | Archivio… | ◐
        tb = ttk.Button(header, text="◐", width=3, bootstyle="secondary-outline",
                        command=self.toggle_theme)
        tb.pack(side="right", padx=(6, 0))
        ToolTip(tb, text="Passa dal tema scuro al tema chiaro e viceversa")
        button(header, "archive", "Archivio…", "secondary-outline", side="right",
               tip="Elenco delle acquisizioni svolte: ricerca, verifica dell'integrità, "
                   "verbali, scarti")
        button(header, "verbale", "Verbale…", "secondary-outline", side="right",
               tip="Compila il verbale delle operazioni per un caso acquisito")
        button(header, "new", "Nuova acquisizione", "success", side="right",
               tip="Archivia o scarta il caso appena concluso e ripulisce l'interfaccia")

        # ================= fascia di stato
        status = ttk.Frame(outer)
        status.pack(fill="x", pady=(12, 10))
        self.banner = ttk.Label(status, text="", font=("Segoe UI", 10, "bold"),
                                bootstyle="inverse-secondary", padding=(14, 8), anchor="w")
        self.banner.pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=160,
                                        bootstyle="info-striped")

        # ================= 1. modalità e piattaforma
        sec1 = ttk.Labelframe(outer, text="  1 · Modalità e piattaforma  ", padding=(12, 8))
        sec1.pack(fill="x")
        sec1.columnconfigure(1, weight=1)

        self.mode = tk.StringVar(value="public")
        ttk.Label(sec1, text="Modalità").grid(row=0, column=0, sticky="w", padx=(0, 12), pady=4)
        mrow = ttk.Frame(sec1)
        mrow.grid(row=0, column=1, sticky="w", pady=4)
        for val, txt, tip in [
                ("public", "  Pagina pubblica (senza login)  ",
                 "Browser pulito, senza cookie né sessioni: dimostra che il contenuto era "
                 "visibile a chiunque. Da preferire quando possibile."),
                ("login", "  Con login  ",
                 "Usa la sessione salvata per la piattaforma scelta, per contenuti visibili "
                 "solo agli utenti registrati.")]:
            rb = ttk.Radiobutton(mrow, text=txt, value=val, variable=self.mode,
                                 bootstyle="info-outline-toolbutton")
            rb.pack(side="left", padx=(0, 6))
            ToolTip(rb, text=tip, wraplength=300)
            self.idle_widgets.append(rb)

        self.name2key = {p["nome"]: k for k, p in PLATFORMS.items()}
        self.platform = tk.StringVar(value=PLATFORMS["facebook"]["nome"])
        ttk.Label(sec1, text="Piattaforma").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=4)
        prow = ttk.Frame(sec1)
        prow.grid(row=1, column=1, sticky="we", pady=4)
        self.cb = ttk.Combobox(prow, textvariable=self.platform, state="readonly",
                               values=list(self.name2key), width=34)
        self.cb.pack(side="left", padx=(0, 10))
        button(prow, "login_start", "Login", "info-outline",
               tip="Apre il browser sulla pagina di accesso. Questa fase NON viene registrata.")
        button(prow, "login_end", "Login completato", "info",
               tip="Chiude il browser e salva la sessione per la piattaforma")
        button(prow, "clear_session", "Elimina sessione", "danger-outline",
               tip="Cancella la sessione salvata per la piattaforma")

        self.custom_login = tk.StringVar()
        ttk.Label(sec1, text="URL di login").grid(row=2, column=0, sticky="w", padx=(0, 12), pady=4)
        self.w_custom = ttk.Entry(sec1, textvariable=self.custom_login)
        self.w_custom.grid(row=2, column=1, sticky="we", pady=4)

        # ================= 2. dati dell'acquisizione
        sec2 = ttk.Labelframe(outer, text="  2 · Dati dell'acquisizione  ", padding=(12, 8))
        sec2.pack(fill="x", pady=(10, 0))
        sec2.columnconfigure(1, weight=1)
        self.vars = {k: tk.StringVar() for k in ("case", "operator", "url", "out")}
        self.vars["out"].set(str(DEFAULT_OUT))
        rows = [("Caso (ID)", "case", "Identificativo del procedimento o della pratica: lettere, "
                                      "numeri, punto, trattino e underscore"),
                ("Operatore", "operator", "Nome e qualifica di chi esegue l'acquisizione"),
                ("URL da acquisire", "url", "Per i social usare il link diretto (permalink) "
                                            "del contenuto, non il feed"),
                ("Cartella output", "out", "Dove vengono salvate le acquisizioni")]
        for i, (lbl, key, tip) in enumerate(rows):
            ttk.Label(sec2, text=lbl).grid(row=i, column=0, sticky="w", padx=(0, 12), pady=4)
            e = ttk.Entry(sec2, textvariable=self.vars[key])
            e.grid(row=i, column=1, columnspan=1 if key == "out" else 2, sticky="we", pady=4)
            ToolTip(e, text=tip, wraplength=300)
            self.idle_widgets.append(e)
        b = ttk.Button(sec2, text="Sfoglia…", bootstyle="secondary-outline", command=self.browse)
        b.grid(row=3, column=2, padx=(8, 0), sticky="e")
        self.idle_widgets.append(b)

        self.tsa = tk.BooleanVar(value=True)
        self.chrome = tk.BooleanVar(value=False)
        opts = ttk.Frame(sec2)
        opts.grid(row=4, column=1, columnspan=2, sticky="w", pady=(6, 2))
        c = ttk.Checkbutton(opts, text="Marca temporale RFC 3161", variable=self.tsa,
                            bootstyle="success-round-toggle")
        c.pack(side="left", padx=(0, 24))
        ToolTip(c, text="Alla chiusura richiede a FreeTSA una marca temporale per il pacchetto. "
                        "Consigliato lasciarla attiva.", wraplength=300)
        self.idle_widgets.append(c)
        c2 = ttk.Checkbutton(opts, text="Usa Google Chrome installato", variable=self.chrome,
                             bootstyle="info-round-toggle")
        c2.pack(side="left")
        ToolTip(c2, text="Usa Chrome al posto del Chromium incluso: utile quando un sito "
                         "ostacola il login. Usare lo stesso browser per login e acquisizione.",
                wraplength=300)
        self.idle_widgets.append(c2)

        self.info = tk.StringVar()
        self.info_label = ttk.Label(sec2, textvariable=self.info, bootstyle="secondary")
        self.info_label.grid(row=5, column=1, columnspan=2, sticky="w", pady=(6, 0))
        sec2.bind("<Configure>", lambda e: self.info_label.configure(
            wraplength=max(300, e.width - 160)))

        # ================= 3. acquisizione
        sec3 = ttk.Labelframe(outer, text="  3 · Acquisizione  ", padding=(12, 10))
        sec3.pack(fill="x", pady=(10, 0))
        button(sec3, "start", "▶   Avvia acquisizione", "success", padx=(0, 4),
               tip="Apre il browser con registrazione di traffico di rete e video "
                   "e carica l'URL da acquisire")
        button(sec3, "expand", "Espandi commenti", "info-outline",
               tip="Apre automaticamente commenti, risposte e testi troncati "
                   "(solo piattaforme supportate). Verificare sempre a vista.")
        button(sec3, "capture", "◉   Acquisisci stato", "primary",
               tip="Cristallizza lo stato attuale della pagina: screenshot, HTML, MHTML e testo")
        button(sec3, "finish", "■   Termina e sigilla", "danger",
               tip="Chiude il browser, calcola le impronte, crea il pacchetto "
                   "e richiede la marca temporale")
        self.stats = ttk.Label(sec3, text="", font=("Segoe UI", 10), bootstyle="secondary")
        self.stats.pack(side="right")

        # ================= registro
        sec4 = ttk.Labelframe(outer, text="  Registro delle operazioni  ", padding=(8, 6))
        sec4.pack(fill="both", expand=True, pady=(10, 0))
        self.logbox = ScrolledText(sec4, height=10, state="disabled", font=("Consolas", 9),
                                   wrap="word", relief="flat", borderwidth=0)
        self.logbox.pack(fill="both", expand=True)
        self.setup_log_tags()

        for var in (self.mode, self.platform, self.vars["url"], self.custom_login):
            var.trace_add("write", lambda *_: self.refresh_controls())
        self.refresh_controls()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.worker.start()
        root.after(100, self.poll)

    # --- helper
    def platform_key(self):
        return self.name2key[self.platform.get()]

    def session_platform(self):
        """Piattaforma che determina le funzioni disponibili per l'acquisizione."""
        if self.mode.get() == "login":
            return self.platform_key()
        return detect_platform(self.vars["url"].get().strip())

    def current_profile(self):
        return profile_dir(self.platform_key(), self.custom_login.get().strip())

    def browse(self):
        d = filedialog.askdirectory(initialdir=self.vars["out"].get())
        if d:
            self.vars["out"].set(d)

    # --- tema e registro
    def toggle_theme(self):
        name = "chiaro" if self.prefs.get("tema", "chiaro") == "scuro" else "scuro"
        self.prefs["tema"] = name
        save_prefs(self.prefs)
        self.root.style.theme_use(THEMES[name])
        self.setup_log_tags()

    def setup_log_tags(self):
        c = self.root.style.colors
        style_text(self.logbox)
        self.logbox.tag_configure("err", foreground=c.danger)
        self.logbox.tag_configure("warn", foreground=c.warning)
        self.logbox.tag_configure("ok", foreground=c.success)
        self.logbox.tag_configure("info", foreground=c.info)

    @staticmethod
    def log_tag(text):
        if "ERRORE" in text:
            return "err"
        if "ATTENZIONE" in text or "Finestra di dialogo" in text:
            return "warn"
        if ("| Cattura " in text or "Marca temporale RFC" in text or "Pacchetto:" in text
                or "Acquisizione archiviata" in text):
            return "ok"
        if "Espansione" in text or "click:" in text or "Navigazione verso" in text:
            return "info"
        return None

    def append_log(self, text):
        self.logbox.configure(state="normal")
        tag = self.log_tag(text)
        self.logbox.insert("end", text + "\n", (tag,) if tag else ())
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    # --- fascia di stato
    def elapsed(self):
        if self.recording and self.rec_start:
            return int(time.time() - self.rec_start)
        return self.rec_elapsed

    def update_banner(self):
        st = self.state
        secs = self.elapsed()
        dur = f"{secs // 60:02d}:{secs % 60:02d}"
        if self.finishing:
            text, style = ("Sigillo in corso: impronte, pacchetto e marca temporale…",
                           "inverse-primary")
        elif self.recording:
            text = (f"●   REGISTRAZIONE IN CORSO   ·   catture: {self.n_captures}   ·   {dur}"
                    + ("   ·   elaborazione…" if st == "busy" else ""))
            style = "inverse-danger"
        elif st == "login":
            text, style = ("●   SESSIONE DI LOGIN APERTA   ·   la navigazione non viene registrata",
                           "inverse-warning")
        elif st == "done":
            text, style = ("✓   ACQUISIZIONE CONCLUSA E SIGILLATA   ·   premi «Nuova acquisizione» "
                           "per proseguire", "inverse-success")
        elif st == "busy":
            text, style = "Elaborazione in corso…", "inverse-primary"
        else:
            text, style = ("Pronto   ·   compila i dati e premi «Avvia acquisizione»",
                           "inverse-secondary")
        if style != self._banner_style:
            self.banner.configure(bootstyle=style)
            self._banner_style = style
        self.banner.configure(text=text)

        if st == "busy" or self.finishing:
            if not self.progress.winfo_ismapped():
                self.progress.pack(side="right", fill="y", padx=(10, 0))
                self.progress.start(12)
        elif self.progress.winfo_ismapped():
            self.progress.stop()
            self.progress.pack_forget()

        if self.recording or st == "done":
            self.stats.configure(text=f"Catture: {self.n_captures}     Durata: {dur}")
        else:
            self.stats.configure(text="")

    def refresh_controls(self):
        st, mode, key = self.state, self.mode.get(), self.platform_key()
        on = set()
        if st == "done":
            on = {"new", "verbale", "archive"}
        elif st == "idle":
            on = {"start", "verbale", "archive"}
            if mode == "login":
                on |= {"login_start", "clear_session"}
        elif st == "login":
            on = {"login_end"}
        elif st == "acquiring":
            on = {"capture", "finish"} | ({"expand"} if self.expand_ok else set())
        for k, b in self.btn.items():
            b.state(["!disabled"] if k in on else ["disabled"])

        idle = st == "idle"
        for w in self.idle_widgets:
            w.state(["!disabled"] if idle else ["disabled"])
        if idle and mode == "login":
            self.cb.state(["!disabled", "readonly"])
        else:
            self.cb.state(["disabled"])
        if idle and mode == "login" and key == "altro":
            self.w_custom.state(["!disabled"])
        else:
            self.w_custom.state(["disabled"])
        self.update_banner()

        if st == "acquiring":
            return
        if st == "done":
            self.info.set("Acquisizione conclusa: premi \"Nuova acquisizione\" per archiviarla "
                          "o scartarla e ripulire l'interfaccia.")
            return
        sp = self.session_platform()
        if sp and PLATFORMS[sp]["espandi"]:
            exp = f"disponibile ({PLATFORMS[sp]['nome']})"
        else:
            exp = "non disponibile per questo sito"
        sess = ""
        if mode == "login" and (key != "altro" or self.custom_login.get().strip()):
            sess = ("   ·   Sessione salvata: sì" if self.current_profile().exists()
                    else "   ·   Sessione salvata: no (esegui il login)")
        self.info.set(f"Espansione automatica dei commenti: {exp}{sess}")

    def set_state(self, state):
        if state == "idle" and self.pending_case:
            state = "done"
        if state == "acquiring" and not self.recording:
            self.recording = True
            self.rec_start = time.time()
            self.n_captures = 0
        if state == "acquiring":
            self.finishing = False
        self.state = state
        self.refresh_controls()

    # --- azioni
    def on_button(self, key):
        if key == "verbale":
            VerbaleDialog(self.root, self.last_case)
            return
        if key == "archive":
            ArchiveWindow(self.root, self.vars["out"].get().strip() or str(DEFAULT_OUT))
            return
        if key == "new":
            self.new_acquisition()
            return
        arg = None
        mode, pkey = self.mode.get(), self.platform_key()

        if key in ("login_start", "clear_session", "start") and mode == "login" \
                and pkey == "altro" and not re.match(r"https?://",
                                                     self.custom_login.get().strip()):
            messagebox.showerror(TOOL_NAME, "Indica l'URL di login del sito "
                                            "(deve iniziare con http:// o https://).")
            return

        if key == "login_start":
            login_url = (self.custom_login.get().strip() if pkey == "altro"
                         else PLATFORMS[pkey]["login_url"])
            arg = {"profile": str(self.current_profile()), "login_url": login_url,
                   "chrome": self.chrome.get(),
                   "nome": PLATFORMS[pkey]["nome"]}

        elif key == "clear_session":
            if not messagebox.askyesno(TOOL_NAME, "Eliminare la sessione salvata per "
                                                  f"{self.platform.get()}? Dovrai rifare il login."):
                return
            arg = {"profile": str(self.current_profile())}

        elif key == "start":
            case = self.vars["case"].get().strip()
            operator = self.vars["operator"].get().strip()
            url = self.vars["url"].get().strip()
            if not re.fullmatch(r"[A-Za-z0-9._-]+", case):
                messagebox.showerror(TOOL_NAME, "Caso: usa solo lettere, numeri, . _ -")
                return
            if not operator:
                messagebox.showerror(TOOL_NAME, "Indica l'operatore.")
                return
            if not re.match(r"https?://", url):
                messagebox.showerror(TOOL_NAME, "L'URL deve iniziare con http:// o https://")
                return
            arg = {"case": case, "operator": operator, "url": url, "mode": mode,
                   "out": self.vars["out"].get().strip() or str(DEFAULT_OUT),
                   "tsa": self.tsa.get(), "chrome": self.chrome.get()}
            if mode == "login":
                prof = self.current_profile()
                if not prof.exists() and not messagebox.askyesno(
                        TOOL_NAME, f"Nessuna sessione salvata per {self.platform.get()}.\n"
                                   "Procedere comunque senza login?"):
                    return
                if pkey != "altro" and detect_platform(url) != pkey and \
                        not messagebox.askyesno(
                            TOOL_NAME, f"L'URL non sembra appartenere a {self.platform.get()}.\n"
                                       "Procedere comunque?"):
                    return
                arg["profile"] = str(prof)
                arg["platform"] = pkey
            else:
                arg["platform"] = detect_platform(url)

        elif key == "finish":
            if not messagebox.askyesno(TOOL_NAME, "Chiudere il browser e sigillare "
                                                  "l'acquisizione? Non sarà più modificabile."):
                return
            self.finishing = True
        self.worker.send(key, arg)

    def poll(self):
        while not self.ui_q.empty():
            kind, data = self.ui_q.get()
            if kind == "log":
                self.append_log(data)
            elif kind == "state":
                self.set_state(data)
            elif kind == "expand":
                self.expand_ok = bool(data)
                self.refresh_controls()
            elif kind == "captures":
                self.n_captures = int(data)
                self.update_banner()
            elif kind == "done":
                self.rec_elapsed = self.elapsed()
                self.recording = False
                self.finishing = False
                self.last_case = data
                self.pending_case = data
                self.set_state("done")
                if messagebox.askyesno(TOOL_NAME, f"Acquisizione completata:\n{data}\n\n"
                                                  "Vuoi compilare ora il verbale delle operazioni?"):
                    VerbaleDialog(self.root, data)
                elif hasattr(os, "startfile"):
                    os.startfile(data)
            elif kind == "fatal":
                messagebox.showerror(TOOL_NAME, f"Errore irreversibile:\n{data}")
        if self.recording:
            tick = int(time.time())
            if tick != self._last_tick:
                self._last_tick = tick
                self.update_banner()
        self.root.after(100, self.poll)

    def new_acquisition(self):
        """Archivia o scarta l'acquisizione conclusa e ripulisce l'interfaccia."""
        case = self.pending_case
        if case and not Path(case).exists():  # già scartata o spostata dall'archivio
            case = None
        if case:
            ans = messagebox.askyesnocancel(
                TOOL_NAME, f"Acquisizione appena conclusa:\n{case}\n\n"
                           "Sì = ARCHIVIA (resta nell'archivio dei casi)\n"
                           "No = SCARTA (spostata tra le acquisizioni scartate)\n"
                           "Annulla = torna indietro")
            if ans is None:
                return
            if ans is False:
                dest = ask_discard(self.root, case)
                if not dest:
                    return
                self.last_case = ""
                note = f"Acquisizione scartata: {dest}"
            else:
                note = f"Acquisizione archiviata: {case}"
        else:
            note = ""
        self.pending_case = None
        self.expand_ok = False
        self.n_captures = 0
        self.rec_elapsed = 0
        for k in ("case", "url"):
            self.vars[k].set("")
        self.logbox.configure(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.configure(state="disabled")
        if note:
            self.append_log(note)
        self.append_log("Pronto per una nuova acquisizione.")
        self.set_state("idle")

    def on_close(self):
        if self.state in ("acquiring", "busy", "login"):
            if not messagebox.askyesno(TOOL_NAME, "Operazione in corso. Uscendo ora "
                                                  "l'eventuale acquisizione NON sarà "
                                                  "sigillata. Uscire?"):
                return
        self.worker.send("quit")
        self.worker.join(timeout=10)
        self.root.destroy()


# =========================================================================== archivio

DISCARD_DIR = "_scartate"


def case_info(case_dir, discarded=False):
    """Dati riassuntivi di un caso, letti dal manifest."""
    case_dir = Path(case_dir)
    try:
        m = json.loads((case_dir / "acquisizione" / "manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return None
    try:
        start = dt.datetime.fromisoformat(m["inizio_utc"]).astimezone()
    except Exception:
        start = None
    verbali = sorted(case_dir.glob("Verbale_*.docx"), key=lambda f: f.stat().st_mtime)
    modalita = m.get("modalita", "")
    return {
        "dir": case_dir,
        "caso": m.get("caso", case_dir.name),
        "inizio": start,
        "url": m.get("url_partenza", ""),
        "piattaforma": m.get("piattaforma", ""),
        "modalita": "con login" if "autenticata" in modalita else "pubblica",
        "operatore": m.get("operatore", ""),
        "catture": len(m.get("catture", [])),
        "verbale": verbali[-1] if verbali else None,
        "tsa": (case_dir / "acquisizione.zip.tsr").exists(),
        "scartata": discarded,
    }


def scan_cases(root, include_discarded=False):
    root = Path(root)
    out = []
    dirs = [(d, False) for d in root.iterdir()] if root.is_dir() else []
    if include_discarded and (root / DISCARD_DIR).is_dir():
        dirs += [(d, True) for d in (root / DISCARD_DIR).iterdir()]
    for d, disc in dirs:
        if d.is_dir() and (d / "acquisizione" / "manifest.json").exists():
            info = case_info(d, disc)
            if info:
                out.append(info)
    out.sort(key=lambda c: c["inizio"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
             reverse=True)
    return out


def verify_case(case_dir):
    """Ricalcola le impronte: pacchetto ZIP e singoli file della cartella acquisizione."""
    case_dir = Path(case_dir)
    res = {"zip": None, "file_ok": 0, "file_ko": [], "mancanti": []}
    zip_path, sha_path = case_dir / "acquisizione.zip", case_dir / "acquisizione.zip.sha256"
    if zip_path.exists() and sha_path.exists():
        expected = sha_path.read_text(encoding="utf-8").split()[0].lower()
        res["zip"] = hash_file(zip_path)[0] == expected
    acq = case_dir / "acquisizione"
    hlist = acq / "hash_sha256.txt"
    if hlist.exists():
        for line in hlist.read_text(encoding="utf-8").splitlines():
            if "  " not in line:
                continue
            h, name = line.split("  ", 1)
            f = acq / name
            if not f.exists():
                res["mancanti"].append(name)
            elif hash_file(f)[0] == h:
                res["file_ok"] += 1
            else:
                res["file_ko"].append(name)
    return res


def _free_path(path):
    path, k = Path(path), 2
    base = path
    while path.exists():
        path = base.with_name(f"{base.name}_{k}")
        k += 1
    return path


def discard_case(case_dir, reason):
    """Sposta il caso nella cartella degli scarti, annotando data e motivo."""
    case_dir = Path(case_dir)
    with open(case_dir / "scarto.txt", "a", encoding="utf-8") as f:
        f.write(f"{dt.datetime.now().astimezone().isoformat(timespec='seconds')} | "
                f"acquisizione scartata dall'utente {getpass.getuser()} | motivo: {reason}\n")
    dest = _free_path(case_dir.parent / DISCARD_DIR / case_dir.name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(case_dir), str(dest))
    return dest


def restore_case(case_dir):
    case_dir = Path(case_dir)
    with open(case_dir / "scarto.txt", "a", encoding="utf-8") as f:
        f.write(f"{dt.datetime.now().astimezone().isoformat(timespec='seconds')} | "
                f"acquisizione ripristinata dall'utente {getpass.getuser()}\n")
    dest = _free_path(case_dir.parent.parent / case_dir.name)
    shutil.move(str(case_dir), str(dest))
    return dest


class ArchiveWindow(tk.Toplevel):
    """Archivio dei casi acquisiti."""

    COLS = [("caso", "Caso", 150), ("data", "Data e ora", 130), ("piattaforma", "Piattaforma", 95),
            ("modalita", "Modalità", 75), ("catture", "Catture", 60), ("verbale", "Verbale", 60),
            ("stato", "Stato", 80), ("url", "URL", 320)]

    def __init__(self, master, root_dir, on_change=None):
        super().__init__(master)
        self.title("Archivio delle acquisizioni")
        self.transient(master)
        self.on_change = on_change
        self.cases = {}

        outer = ttk.Frame(self, padding=10)
        outer.pack(fill="both", expand=True)
        top = ttk.Frame(outer)
        top.pack(fill="x")
        ttk.Label(top, text="Cartella archivio").pack(side="left")
        self.root_dir = tk.StringVar(value=str(root_dir))
        ttk.Entry(top, textvariable=self.root_dir).pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(top, text="Sfoglia…", command=self.browse).pack(side="left")

        flt = ttk.Frame(outer)
        flt.pack(fill="x", pady=(8, 4))
        ttk.Label(flt, text="Cerca").pack(side="left")
        self.query = tk.StringVar()
        ttk.Entry(flt, textvariable=self.query, width=40).pack(side="left", padx=6)
        self.show_disc = tk.BooleanVar(value=False)
        ttk.Checkbutton(flt, text="Mostra acquisizioni scartate", variable=self.show_disc,
                        command=self.refresh, bootstyle="warning-round-toggle").pack(side="left", padx=10)
        ttk.Button(flt, text="Aggiorna", bootstyle="secondary-outline",
                   command=self.refresh).pack(side="right")
        self.query.trace_add("write", lambda *_: self.fill())

        # --- azioni in basso: impacchettate PRIMA dell'elenco, così restano sempre visibili
        bar = ttk.Frame(outer)
        bar.pack(side="bottom", fill="x", pady=(6, 0))
        row1 = ttk.Frame(bar)
        row1.pack(fill="x")
        row2 = ttk.Frame(bar)
        row2.pack(fill="x", pady=(6, 0))
        styles = {"open": "secondary-outline", "verbale_open": "secondary-outline",
                  "verbale_new": "primary-outline", "verify": "info", "discard": "warning-outline",
                  "restore": "success-outline", "delete": "danger"}
        self.b = {}
        for parent, key, text, cmd in [
                (row1, "open", "Apri cartella", self.open_folder),
                (row1, "verbale_open", "Apri verbale", self.open_verbale),
                (row1, "verbale_new", "Genera verbale…", self.new_verbale),
                (row1, "verify", "Verifica integrità", self.verify),
                (row2, "discard", "Scarta", self.discard),
                (row2, "restore", "Ripristina", self.restore),
                (row2, "delete", "Elimina definitivamente", self.delete)]:
            btn = ttk.Button(parent, text=text, command=cmd, bootstyle=styles[key])
            btn.pack(side="left", padx=(0, 6))
            self.b[key] = btn
        ttk.Button(row2, text="Chiudi", bootstyle="secondary",
                   command=self.destroy).pack(side="right")
        self.detail = tk.StringVar()
        ttk.Label(outer, textvariable=self.detail, bootstyle="secondary").pack(
            side="bottom", fill="x", pady=(6, 0))

        ttk.Label(outer, text="Seleziona un'acquisizione nell'elenco per attivare le azioni; "
                              "doppio clic per aprirne la cartella.", bootstyle="info").pack(
            anchor="w", pady=(2, 4))
        tf = ttk.Frame(outer)
        tf.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tf, columns=[c[0] for c in self.COLS], show="headings",
                                 selectmode="browse", height=12)
        for key, label, width in self.COLS:
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor="w", stretch=(key == "url"))
        sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("scartata", foreground="#999")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.update_buttons())
        self.tree.bind("<Double-1>", lambda e: self.open_folder())

        self.minsize(760, 460)
        center(self, 1060, 600)
        self.refresh()

    # --- dati
    def browse(self):
        d = filedialog.askdirectory(parent=self, initialdir=self.root_dir.get())
        if d:
            self.root_dir.set(d)
            self.refresh()

    def refresh(self):
        try:
            data = scan_cases(self.root_dir.get(), self.show_disc.get())
        except Exception as e:
            messagebox.showerror(TOOL_NAME, f"Impossibile leggere l'archivio:\n{e}", parent=self)
            data = []
        self.all = data
        self.fill()

    def fill(self):
        self.tree.delete(*self.tree.get_children())
        self.cases = {}
        q = self.query.get().strip().lower()
        for i, c in enumerate(self.all):
            if q and q not in (c["caso"] + " " + c["url"] + " " + c["operatore"]).lower():
                continue
            iid = str(i)
            self.cases[iid] = c
            self.tree.insert("", "end", iid=iid, tags=("scartata",) if c["scartata"] else (),
                             values=(c["caso"],
                                     c["inizio"].strftime("%d/%m/%Y %H:%M") if c["inizio"] else "",
                                     c["piattaforma"], c["modalita"], c["catture"],
                                     "sì" if c["verbale"] else "no",
                                     "scartata" if c["scartata"] else "archiviata", c["url"]))
        n = len(self.cases)
        self.detail.set(f"{n} acquisizion{'e' if n == 1 else 'i'} trovat{'a' if n == 1 else 'e'}")
        self.update_buttons()

    def selected(self):
        sel = self.tree.selection()
        return self.cases.get(sel[0]) if sel else None

    def update_buttons(self):
        c = self.selected()
        rules = {
            "open": bool(c), "verify": bool(c),
            "verbale_open": bool(c and c["verbale"]),
            "verbale_new": bool(c and not c["scartata"]),
            "discard": bool(c and not c["scartata"]),
            "restore": bool(c and c["scartata"]),
            "delete": bool(c and c["scartata"]),
        }
        for k, on in rules.items():
            self.b[k].state(["!disabled"] if on else ["disabled"])
        if c:
            self.detail.set(f"{c['dir']}  |  operatore: {c['operatore']}  |  marca temporale: "
                            f"{'sì' if c['tsa'] else 'no'}")

    def changed(self):
        self.refresh()
        if self.on_change:
            self.on_change()

    # --- azioni
    def open_folder(self):
        c = self.selected()
        if c and hasattr(os, "startfile"):
            os.startfile(str(c["dir"]))

    def open_verbale(self):
        c = self.selected()
        if c and c["verbale"] and hasattr(os, "startfile"):
            os.startfile(str(c["verbale"]))

    def new_verbale(self):
        c = self.selected()
        if c:
            dlg = VerbaleDialog(self, str(c["dir"]))
            self.wait_window(dlg)
            self.refresh()

    def verify(self):
        c = self.selected()
        if not c:
            return
        self.config(cursor="watch")
        self.detail.set("Verifica delle impronte in corso…")
        result = []
        threading.Thread(target=lambda: result.append(verify_case(c["dir"])), daemon=True).start()

        def wait():
            if not result:
                self.after(200, wait)
                return
            self.config(cursor="")
            r = result[0]
            ok = r["zip"] is not False and not r["file_ko"] and not r["mancanti"]
            lines = [f"Caso: {c['caso']}", ""]
            lines.append("Pacchetto acquisizione.zip: " + {True: "impronta CORRISPONDENTE",
                                                           False: "impronta NON CORRISPONDENTE",
                                                           None: "pacchetto o impronta non trovati"}[r["zip"]])
            lines.append(f"File della cartella acquisizione corrispondenti: {r['file_ok']}")
            if r["file_ko"]:
                lines.append("File MODIFICATI: " + ", ".join(r["file_ko"]))
            if r["mancanti"]:
                lines.append("File MANCANTI: " + ", ".join(r["mancanti"]))
            (messagebox.showinfo if ok else messagebox.showwarning)(
                TOOL_NAME, "\n".join(lines), parent=self)
            self.update_buttons()
        wait()

    def discard(self):
        c = self.selected()
        if c and ask_discard(self, c["dir"]):
            self.changed()

    def restore(self):
        c = self.selected()
        if not c:
            return
        try:
            restore_case(c["dir"])
        except Exception as e:
            messagebox.showerror(TOOL_NAME, f"Ripristino non riuscito:\n{e}", parent=self)
        self.changed()

    def delete(self):
        c = self.selected()
        if not c:
            return
        if not messagebox.askyesno(TOOL_NAME, f"Eliminare DEFINITIVAMENTE l'acquisizione "
                                              f"\"{c['caso']}\"?\n\n{c['dir']}\n\n"
                                              "L'operazione non è reversibile.",
                                   icon="warning", parent=self):
            return
        try:
            shutil.rmtree(c["dir"])
        except Exception as e:
            messagebox.showerror(TOOL_NAME, f"Eliminazione non riuscita:\n{e}", parent=self)
        self.changed()


def ask_discard(parent, case_dir):
    """Chiede conferma e motivo dello scarto; restituisce il nuovo percorso o None."""
    reason = simpledialog.askstring(
        TOOL_NAME, "Motivo dello scarto (es. acquisizione di prova, pagina errata, "
                   "acquisizione incompleta):", parent=parent)
    if reason is None:
        return None
    if not reason.strip():
        messagebox.showerror(TOOL_NAME, "Indica il motivo dello scarto.", parent=parent)
        return None
    try:
        return discard_case(case_dir, reason.strip())
    except Exception as e:
        messagebox.showerror(TOOL_NAME, f"Scarto non riuscito:\n{e}", parent=parent)
        return None


# =========================================================================== verbale

def verbale_tabs():
    """Schede della procedura guidata del verbale (richiede il modulo verbale caricato)."""
    return [
        ("Intestazione e riferimenti", [
            ("tipo_atto", "Tipo di verbale", "combo", list(V.TIPI_ATTO),
             "«Generico» va bene per chiunque; gli altri tipi sono per gli atti di polizia giudiziaria"),
            ("stemma", "Logo o stemma", "stemma", None,
             "Facoltativo: immagine PNG o JPG inserita centrata in cima al verbale"),
            ("intestazione", "Intestazione", "text", 3,
             "Facoltativa, una riga per livello (es. nome dello studio, dell'ente o dell'ufficio). "
             "Se resta vuota, il verbale non ha intestazione"),
            ("procedimento", "Riferimento", "entry", None,
             "Facoltativo: numero di pratica, incarico o procedimento"),
            ("autorita", "Autorità o committente", "entry", None,
             "Facoltativo: per chi è svolta l'attività"),
            ("pm", "Pubblico Ministero", "entry", None, "Solo per gli atti di polizia giudiziaria"),
            ("data_delega", "Data della delega", "entry", None,
             "Solo per il verbale su delega del Pubblico Ministero"),
            ("comune", "Luogo", "entry", None, "Comune in cui si svolgono le operazioni"),
            ("presso", "Presso", "entry", None, "Facoltativo: es. presso lo studio di ..., presso la sede di ..."),
        ]),
        ("Operatori", [
            ("operatori", "Operatori", "text", 5,
             "Una riga per persona:  Nome e cognome | Qualifica | Ente o organizzazione "
             "(qualifica ed ente sono facoltativi)"),
            ("presenti", "Altri presenti", "text", 3,
             "Facoltativo, uno per riga (es. consulente, testimone, difensore...)"),
        ]),
        ("Operazioni", [
            ("motivo", "Oggetto e motivi", "text", 5,
             "Ragioni dell'attività: incarico, richiesta, contenuti da documentare..."),
            ("account", "Account utilizzato", "entry", None, "solo per acquisizioni con login"),
            ("note_operazioni", "Note sulle operazioni", "text", 3, "Facoltativo"),
        ]),
        ("Supporti e custodia", [
            ("supporti", "Supporti", "text", 4,
             "Una riga per supporto:  Tipo | Marca e modello | N. di serie | Capacità"),
            ("custodia", "Custodia", "text", 4, "Destinazione e custodia dei supporti"),
            ("note", "Annotazioni finali", "text", 3, "Facoltativo"),
        ]),
    ]


class ScrollFrame(ttk.Frame):
    """Contenitore con barra di scorrimento verticale: i campi restano sempre raggiungibili."""

    def __init__(self, master, padding=12):
        super().__init__(master)
        try:
            bg = ttk.Style().colors.bg
        except Exception:
            bg = None
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0,
                                **({"background": bg} if bg else {}))
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas, padding=padding)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.vsb.pack(side="right", fill="y")
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._win, width=e.width))

    def scroll(self, event):
        if isinstance(event.widget, tk.Text):  # il campo di testo scorre per conto suo
            return
        if self.canvas.yview() != (0.0, 1.0):
            self.canvas.yview_scroll(int(-event.delta / 120), "units")


VERBALE_TAB_INFO = [
    "Tipo di verbale e dati facoltativi di presentazione. Tutti i campi possono restare vuoti; "
    "tipo, logo, intestazione, luogo e committente vengono ricordati per le volte successive.",
    "Chi ha eseguito le operazioni ed eventuali altri presenti. Gli operatori vengono "
    "ricordati per le volte successive.",
    "Perché è stata svolta l'attività. Orari, indirizzi, catture, impronte e marca temporale "
    "vengono inseriti automaticamente dai dati dell'acquisizione.",
    "Su quali supporti è stato copiato il pacchetto e dove sono custoditi. Se i supporti non "
    "sono ancora pronti, puoi generare il verbale più tardi dall'archivio.",
]


class VerbaleDialog(tk.Toplevel):
    """Procedura guidata per la compilazione e la generazione del verbale in Word."""

    def __init__(self, master, case_dir=""):
        super().__init__(master)
        self.title("Verbale delle operazioni compiute")
        self.transient(master)
        st = V.load_settings(SETTINGS_FILE)
        self.fields = {}

        outer = ttk.Frame(self, padding=(16, 12, 16, 12))
        outer.pack(fill="both", expand=True)

        # --- titolo e istruzioni
        ttk.Label(outer, text="Verbale delle operazioni", font=("Segoe UI", 15, "bold"),
                  bootstyle="primary").pack(anchor="w")
        ttk.Label(outer, text="Scegli il caso, compila le quattro schede spostandoti con "
                              "«Avanti» e premi «Genera verbale». I campi lasciati vuoti "
                              "diventano segnaposto gialli da completare in Word.",
                  bootstyle="secondary", wraplength=760, justify="left").pack(
            anchor="w", fill="x", pady=(2, 10))

        # --- pulsanti in basso: impacchettati PRIMA del contenuto, così restano sempre visibili
        bar = ttk.Frame(outer)
        bar.pack(side="bottom", fill="x", pady=(10, 0))
        ttk.Button(bar, text="Annulla", bootstyle="secondary-outline",
                   command=self.destroy).pack(side="left")
        self.b_generate = ttk.Button(bar, text="✓  Genera verbale", bootstyle="success",
                                     command=self.generate)
        self.b_generate.pack(side="right")
        self.b_next = ttk.Button(bar, text="Avanti  ▶", bootstyle="primary",
                                 command=lambda: self.go(1))
        self.b_next.pack(side="right", padx=(0, 8))
        self.b_prev = ttk.Button(bar, text="◀  Indietro", bootstyle="primary-outline",
                                 command=lambda: self.go(-1))
        self.b_prev.pack(side="right", padx=(0, 6))
        self.step = ttk.Label(bar, text="", bootstyle="secondary")
        self.step.pack(side="right", padx=(0, 14))
        ttk.Separator(outer).pack(side="bottom", fill="x", pady=(8, 0))

        # --- caso
        cbox = ttk.Labelframe(outer, text="  Caso  ", padding=(12, 8))
        cbox.pack(fill="x")
        crow = ttk.Frame(cbox)
        crow.pack(fill="x")
        ttk.Label(crow, text="Cartella del caso").pack(side="left")
        self.case = tk.StringVar(value=case_dir)
        ttk.Entry(crow, textvariable=self.case).pack(side="left", padx=8, fill="x", expand=True)
        ttk.Button(crow, text="Sfoglia…", bootstyle="secondary-outline",
                   command=self.browse).pack(side="left")
        self.case_info = ttk.Label(cbox, text="", wraplength=760, justify="left")
        self.case_info.pack(anchor="w", pady=(6, 0))
        self.case.trace_add("write", lambda *_: self.update_case_info())

        # --- schede
        self.nb = ttk.Notebook(outer)
        self.nb.pack(fill="both", expand=True, pady=(10, 0))
        self.tabs = []
        for idx, (tab_title, fields) in enumerate(verbale_tabs()):
            sf = ScrollFrame(self.nb)
            self.nb.add(sf, text=f"  {idx + 1} · {tab_title}  ")
            self.tabs.append((tab_title, sf))
            tab = sf.inner
            tab.columnconfigure(1, weight=1)
            ttk.Label(tab, text=VERBALE_TAB_INFO[idx], bootstyle="info", wraplength=700,
                      justify="left").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
            row = 1
            for key, label, kind, opt, hint in fields:
                ttk.Label(tab, text=label).grid(row=row, column=0, sticky="nw", padx=(0, 12),
                                                pady=(4, 2))
                value = st.get(key, "")
                if kind == "stemma":
                    w = self.stemma_widget(tab, st)
                elif kind == "text":
                    w = tk.Text(tab, height=opt, width=60, wrap="word", font=("Segoe UI", 9),
                                relief="flat", padx=6, pady=4)
                    style_text(w)
                    w.insert("1.0", value)
                elif kind == "combo":
                    var = tk.StringVar(value=value or opt[0])
                    w = ttk.Combobox(tab, textvariable=var, values=opt, state="readonly")
                    w.var = var
                else:
                    var = tk.StringVar(value=value)
                    w = ttk.Entry(tab, textvariable=var)
                    w.var = var
                w.grid(row=row, column=1, sticky="we", pady=(4, 2))
                self.fields[key] = (kind, w)
                row += 1
                if hint:
                    ttk.Label(tab, text=hint, bootstyle="secondary", wraplength=600,
                              justify="left").grid(row=row, column=1, sticky="w", pady=(0, 6))
                    row += 1
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.update_nav())
        # rotella del mouse: scorre la scheda visibile
        self.bind_all("<MouseWheel>", lambda e: self.tabs[self.nb.index("current")][1].scroll(e))
        self.bind("<Destroy>", lambda e: self.unbind_all("<MouseWheel>") if e.widget is self else None)

        self.update_case_info()
        self.update_nav()
        self.fit_to_screen()
        self.grab_set()

    # --- dimensionamento: mostra tutto se c'è spazio, altrimenti le schede scorrono
    def fit_to_screen(self):
        self.update_idletasks()
        tallest = max(sf.inner.winfo_reqheight() for _, sf in self.tabs)
        for _, sf in self.tabs:
            sf.canvas.configure(height=tallest)
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w = min(max(self.winfo_reqwidth(), 900), sw - 40)
        h = min(self.winfo_reqheight(), sh - 90)
        self.minsize(min(760, w), min(520, h))
        center(self, w, h)

    # --- navigazione tra le schede
    def go(self, delta):
        i = self.nb.index("current") + delta
        if 0 <= i < len(self.tabs):
            self.nb.select(i)

    def update_nav(self):
        i = self.nb.index("current")
        n = len(self.tabs)
        self.step.configure(text=f"Passo {i + 1} di {n}  ·  {self.tabs[i][0]}")
        self.b_prev.state(["!disabled"] if i > 0 else ["disabled"])
        self.b_next.state(["!disabled"] if i < n - 1 else ["disabled"])

    def update_case_info(self):
        path = self.case.get().strip()
        info = case_info(path) if path and (Path(path) / "acquisizione" / "manifest.json").exists() \
            else None
        if info:
            when = info["inizio"].strftime("%d/%m/%Y alle %H:%M") if info["inizio"] else ""
            self.case_info.configure(
                text=f"✓  Caso {info['caso']}  ·  acquisito il {when}  ·  {info['catture']} "
                     f"catture  ·  {info['url']}", bootstyle="success")
        else:
            self.case_info.configure(
                text="Nessun caso valido selezionato: premi «Sfoglia…» e scegli la cartella del "
                     "caso (es. PRATICA-001_20261001T143015Z), non la sottocartella "
                     "«acquisizione».", bootstyle="warning")

    def browse(self):
        d = filedialog.askdirectory(parent=self, initialdir=self.case.get() or str(DEFAULT_OUT),
                                    title="Seleziona la cartella del caso")
        if d:
            self.case.set(d)

    def stemma_widget(self, parent, st):
        """Casella, file immagine e larghezza dello stemma."""
        # ordine di preferenza: immagine scelta dall'utente, copia locale, stemma incluso
        candidates = [st.get("stemma_file") or "", DATA_DIR / "stemma.png",
                      DATA_DIR / "stemma.jpg", resource_path("stemma_repubblica.png")]
        default = next((str(f) for f in candidates if f and Path(f).is_file()), "")
        # attivo di norma solo se un'immagine è disponibile (la versione Store non include l'emblema)
        self.st_on = tk.BooleanVar(value=bool(st.get("stemma_attivo", False)) and bool(default))
        self.st_file = tk.StringVar(value=default)
        self.st_cm = tk.StringVar(value=str(st.get("stemma_cm") or "1.8"))
        box = ttk.Frame(parent)
        ttk.Checkbutton(box, text="Inserisci", variable=self.st_on,
                        bootstyle="success-round-toggle").pack(side="left")
        ttk.Entry(box, textvariable=self.st_file, state="readonly").pack(
            side="left", fill="x", expand=True, padx=6)
        ttk.Button(box, text="Scegli immagine…", command=self.choose_stemma).pack(side="left")
        if resource_path("stemma_repubblica.png").is_file():
            ttk.Button(box, text="Stemma predefinito", command=self.default_stemma).pack(
                side="left", padx=(4, 0))
        ttk.Label(box, text="Larghezza (cm)").pack(side="left", padx=(10, 4))
        ttk.Spinbox(box, from_=0.8, to=5.0, increment=0.1, width=5,
                    textvariable=self.st_cm).pack(side="left")
        return box

    def default_stemma(self):
        f = resource_path("stemma_repubblica.png")
        if f.is_file():
            self.st_file.set(str(f))
            self.st_on.set(True)
        else:
            messagebox.showerror(TOOL_NAME, "Stemma predefinito non trovato nel pacchetto.",
                                 parent=self)

    def choose_stemma(self):
        f = filedialog.askopenfilename(parent=self, title="Immagine dello stemma",
                                       filetypes=[("Immagini", "*.png *.jpg *.jpeg"),
                                                  ("Tutti i file", "*.*")])
        if not f:
            return
        src = Path(f)
        # copia accanto al programma, così resta disponibile anche se l'originale viene spostato
        dest = DATA_DIR / ("stemma" + src.suffix.lower().replace(".jpeg", ".jpg"))
        try:
            if src.resolve() != dest.resolve():
                shutil.copyfile(src, dest)
        except Exception as e:
            messagebox.showerror(TOOL_NAME, f"Impossibile copiare l'immagine:\n{e}", parent=self)
            return
        self.st_file.set(str(dest))
        self.st_on.set(True)

    def values(self):
        out = {}
        for key, (kind, w) in self.fields.items():
            if kind == "stemma":
                out["stemma_attivo"] = self.st_on.get()
                out["stemma_file"] = self.st_file.get().strip()
                out["stemma_cm"] = self.st_cm.get().strip()
            else:
                out[key] = w.get("1.0", "end").strip() if kind == "text" else w.var.get().strip()
        return out

    def generate(self):
        case = Path(self.case.get().strip())
        if not (case / "acquisizione" / "manifest.json").exists():
            messagebox.showerror(TOOL_NAME, "Seleziona la cartella di un caso acquisito "
                                            "(deve contenere acquisizione\\manifest.json).", parent=self)
            return
        d = self.values()
        if d["stemma_attivo"] and not Path(d["stemma_file"]).is_file():
            messagebox.showerror(TOOL_NAME, "Scegli l'immagine dello stemma oppure togli la "
                                            "spunta da \"Inserisci\".", parent=self)
            return
        try:
            V.save_settings(SETTINGS_FILE, d)
            path = V.generate_verbale(case, d)
        except Exception as e:
            messagebox.showerror(TOOL_NAME, f"Errore nella generazione del verbale:\n{e}",
                                 parent=self)
            return
        messagebox.showinfo(TOOL_NAME, f"Verbale creato:\n{path}", parent=self)
        if hasattr(os, "startfile"):
            os.startfile(str(path))
        self.destroy()


def center(win, w, h):
    win.update_idletasks()
    w = min(w, win.winfo_screenwidth() - 40)
    h = min(h, win.winfo_screenheight() - 90)
    x = max(0, (win.winfo_screenwidth() - w) // 2)
    y = max(0, (win.winfo_screenheight() - h) // 2)
    win.geometry(f"{w}x{h}+{x}+{y}")


def load_heavy_modules(status):
    """Carica in sottofondo le librerie pesanti. 'status' è un dizionario condiviso con lo
    splash: 'target' (0-1) indica fin dove può avanzare la barra, 'text' la fase in corso."""
    global V
    status.update(target=0.20, text="Avvio del motore del browser…")
    import playwright.sync_api  # noqa: F401  (il modulo più pesante)
    status.update(target=0.65, text="Caricamento del modulo dei verbali…")
    import verbale
    V = verbale
    status.update(target=0.85, text="Preparazione dell'interfaccia…")


class Splash:
    """Schermata di avvio con barra di caricamento, visibile subito all'apertura."""
    BAR_H = 48
    BG, TRACK, FILL, TEXT = "#0b0a1e", "#2b2950", "#ff2a3c", "#e8e8f5"

    def __init__(self, root):
        self.win = tk.Toplevel(root)
        self.win.overrideredirect(True)
        try:
            self.win.attributes("-topmost", True)
        except tk.TclError:
            pass
        self.win.configure(background=self.BG)
        path = resource_path("splash.png")
        self.img = tk.PhotoImage(file=str(path)) if path.exists() else None
        width = self.img.width() if self.img else 520
        if self.img:
            lbl = tk.Label(self.win, image=self.img, borderwidth=0, highlightthickness=0)
            lbl.configure(background=self.BG)
            lbl.pack()
        self.w = width
        self.cv = tk.Canvas(self.win, width=width, height=self.BAR_H, highlightthickness=0,
                            borderwidth=0)
        self.cv.configure(background=self.BG)  # dopo la creazione: prevale su eventuali temi
        self.cv.pack()
        pad = 22
        self.x0, self.x1, self.y = pad, width - pad, 30
        self.txt = self.cv.create_text(pad, 13, anchor="w", fill=self.TEXT,
                                       font=("Segoe UI", 9), text="Avvio in corso…")
        self.pct = self.cv.create_text(width - pad, 13, anchor="e", fill=self.TEXT,
                                       font=("Segoe UI", 9, "bold"), text="0%")
        self.cv.create_rectangle(self.x0, self.y, self.x1, self.y + 6, fill=self.TRACK, width=0)
        self.bar = self.cv.create_rectangle(self.x0, self.y, self.x0, self.y + 6,
                                            fill=self.FILL, width=0)
        self.value = 0.0
        center(self.win, width, (self.img.height() if self.img else 0) + self.BAR_H)
        self.win.update()  # mostra subito lo splash

    def show(self, value, text):
        self.value = value
        x = self.x0 + (self.x1 - self.x0) * max(0.0, min(1.0, value))
        self.cv.coords(self.bar, self.x0, self.y, x, self.y + 6)
        self.cv.itemconfigure(self.pct, text=f"{int(value * 100)}%")
        self.cv.itemconfigure(self.txt, text=text)

    def close(self):
        self.win.destroy()


def main():
    t0 = time.time()
    prefs = load_prefs()
    root = ttk.Window(themename=THEMES.get(prefs.get("tema"), "flatly"))
    root.withdraw()
    try:
        root.iconbitmap(default=str(resource_path("icon.ico")))
    except Exception:
        pass
    splash = Splash(root)

    # caricamento delle librerie pesanti in sottofondo: la barra resta animata
    status = {"target": 0.05, "text": "Avvio in corso…", "done": False, "error": None}

    def loader():
        try:
            load_heavy_modules(status)
        except Exception:
            import traceback
            status["error"] = traceback.format_exc()
        status["done"] = True

    threading.Thread(target=loader, daemon=True).start()
    phase = {"app": False}

    def show_main():
        root.update_idletasks()
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        need_w = root.winfo_reqwidth()
        # larghezza minima calcolata sul contenuto: i pulsanti restano sempre leggibili
        root.minsize(min(need_w, sw - 20), min(600, sh - 80))
        # dimensione usata quando si "ripristina" la finestra dal tutto schermo
        center(root, max(WINDOW_SIZE[0], need_w), WINDOW_SIZE[1])
        root.deiconify()
        try:
            root.state("zoomed")              # Windows: finestra massimizzata
        except tk.TclError:
            try:
                root.attributes("-zoomed", True)  # altri sistemi
            except tk.TclError:
                pass
        root.lift()
        root.focus_force()

    def tick():
        elapsed = time.time() - t0
        if status["done"] and status["error"]:
            splash.close()
            messagebox.showerror(TOOL_NAME, "Impossibile avviare il programma:\n\n"
                                 + status["error"][-1500:])
            root.destroy()
            return
        if status["done"] and not phase["app"]:
            # librerie pronte: si costruisce l'interfaccia mentre lo splash resta visibile
            splash.show(max(splash.value, 0.85), "Preparazione dell'interfaccia…")
            root.update_idletasks()
            App(root)
            install_context_menu(root)
            phase["app"] = True
            status.update(target=1.0, text="Pronto")
        # la barra avanza in modo continuo, senza superare la fase raggiunta né
        # completarsi prima della durata minima dello splash
        cap = 0.15 + 0.85 * min(1.0, elapsed / MIN_SPLASH_S)
        target = min(status["target"], cap)
        value = splash.value + (target - splash.value) * 0.12
        splash.show(value, status["text"])
        if phase["app"] and elapsed >= MIN_SPLASH_S and value > 0.985:
            splash.show(1.0, "Pronto")
            root.after(150, lambda: (splash.close(), show_main()))
            return
        root.after(30, tick)

    root.after(30, tick)
    root.mainloop()


if __name__ == "__main__":
    main()
