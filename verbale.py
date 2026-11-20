# -*- coding: utf-8 -*-
"""
verbale.py - Generazione del verbale di acquisizione (Word) per Web Forensic Extractor.

Copyright (C) 2026 Giovanni Ciccarese
Concesso in licenza a norma dell'EUPL, versione 1.2 o successive (vedi LICENZA.txt e AVVISI.txt).
SPDX-License-Identifier: EUPL-1.2

I dati tecnici sono letti dalla cartella del caso (manifest, registri, impronte);
i dati dell'atto (intestazione, procedimento, operatori, supporti...) sono passati
dall'interfaccia. I campi mancanti vengono inseriti come segnaposto evidenziati in giallo.
"""

import datetime as dt
import json
import re
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_COLOR_INDEX
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt

MESI = ["gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio",
        "agosto", "settembre", "ottobre", "novembre", "dicembre"]

GENERICO = "Verbale di acquisizione forense (generico)"

# titolo, sottotitolo con riferimento normativo (None = nessuno)
TIPI_ATTO = {
    GENERICO:
        ("VERBALE DI ACQUISIZIONE FORENSE", None),
    "Verbale di operazioni compiute (art. 357 c.p.p.)":
        ("VERBALE DI OPERAZIONI COMPIUTE", "(art. 357 c.p.p.)"),
    "Verbale di accertamenti urgenti su dati informatici (art. 354, c. 2, c.p.p.)":
        ("VERBALE DI ACCERTAMENTI URGENTI SU DATI INFORMATICI", "(art. 354, comma 2, c.p.p.)"),
    "Verbale di operazioni compiute su delega del P.M. (artt. 370 e 357 c.p.p.)":
        ("VERBALE DI OPERAZIONI COMPIUTE SU DELEGA DEL PUBBLICO MINISTERO",
         "(artt. 370 e 357 c.p.p.)"),
}

# Campi ricordati tra un verbale e l'altro
CAMPI_PERSISTENTI = ["stemma_attivo", "stemma_file", "stemma_cm",
                     "intestazione", "comune", "presso", "tipo_atto", "autorita",
                     "operatori", "custodia"]

# Nessun testo di custodia predefinito: se il campo è vuoto compare un segnaposto da completare
DEFAULT_CUSTODIA = ""


# =========================================================================== impostazioni

def load_settings(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {"tipo_atto": GENERICO, "stemma_attivo": False}


def save_settings(path, data):
    keep = {k: data.get(k, "") for k in CAMPI_PERSISTENTI}
    Path(path).write_text(json.dumps(keep, indent=2, ensure_ascii=False), encoding="utf-8")


# =========================================================================== lettura caso

def _loc(iso):
    """Da ISO UTC a ora locale del sistema."""
    return dt.datetime.fromisoformat(iso).astimezone()


def _ora(d):
    return d.strftime("%H:%M:%S")


def _data(d):
    return f"{d.day} {MESI[d.month - 1]} {d.year}"


def read_case(case_dir):
    case_dir = Path(case_dir)
    acq = case_dir / "acquisizione"
    manifest_path = acq / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.json non trovato in {acq}")
    m = json.loads(manifest_path.read_text(encoding="utf-8"))

    # eventi dal registro dell'acquisizione
    events = []
    log_path = acq / "acquisizione.log"
    if log_path.exists():
        exp_start = None
        for line in log_path.read_text(encoding="utf-8").splitlines():
            if " | " not in line:
                continue
            ts, msg = line.split(" | ", 1)
            try:
                t = _loc(ts)
            except ValueError:
                continue
            if msg.startswith("Navigazione verso "):
                events.append((t, "nav", msg[len("Navigazione verso "):]))
            elif msg.startswith("Espansione automatica"):
                exp_start = t
            elif msg.startswith("Espansione terminata"):
                n = re.search(r"(\d+) click", msg)
                events.append((exp_start or t, "expand", int(n.group(1)) if n else 0))
            elif msg.startswith("Cattura "):
                mm = re.match(r"Cattura (\d+) \| URL: (.*?) \| Titolo: (.*)$", msg)
                if mm:
                    events.append((t, "capture", (int(mm.group(1)), mm.group(2), mm.group(3))))
            elif msg.startswith("Finestra di dialogo del sito"):
                events.append((t, "dialog", msg))
            elif msg.startswith("Chiusura browser"):
                events.append((t, "close", None))

    # pacchetto e marca temporale
    pkg = {"sha256": None, "md5": None, "tsa_time": None, "tsa_serial": None, "tsa_url": None}
    clog = case_dir / "chiusura.log"
    if clog.exists():
        for line in clog.read_text(encoding="utf-8").splitlines():
            mm = re.search(r"SHA-256: ([0-9a-f]{64}) \| MD5: ([0-9a-f]{32})", line)
            if mm:
                pkg["sha256"], pkg["md5"] = mm.group(1), mm.group(2)
            mm = re.search(r"Marca temporale RFC 3161 \((.*?)\)", line)
            if mm:
                pkg["tsa_url"] = mm.group(1)
            mm = re.search(r"Data/ora certificata \(UTC\): (.+)$", line)
            if mm:
                pkg["tsa_time"] = mm.group(1).strip()
            mm = re.search(r"Numero di serie: (.+)$", line)
            if mm:
                pkg["tsa_serial"] = mm.group(1).strip()

    # elenco file con impronte
    files = []
    hlist = acq / "hash_sha256.txt"
    if hlist.exists():
        for line in hlist.read_text(encoding="utf-8").splitlines():
            if "  " in line:
                h, name = line.split("  ", 1)
                f = acq / name
                files.append((name, f.stat().st_size if f.exists() else None, h))
    return {"dir": case_dir, "m": m, "events": events, "pkg": pkg, "files": files}


# =========================================================================== helper docx

def _set_cell_bg(cell, color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), color)
    tcPr.append(shd)


def _field(paragraph, instr, size=None):
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), instr)
    r = OxmlElement("w:r")
    if size:
        rpr = OxmlElement("w:rPr")
        sz = OxmlElement("w:sz")
        sz.set(qn("w:val"), str(size * 2))
        rpr.append(sz)
        r.append(rpr)
    t = OxmlElement("w:t")
    t.text = "1"
    r.append(t)
    fld.append(r)
    paragraph._p.append(fld)


class Writer:
    def __init__(self):
        self.doc = Document()
        st = self.doc.styles["Normal"]
        st.font.name = "Times New Roman"
        st.font.size = Pt(12)
        st.element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")
        st.paragraph_format.space_after = Pt(6)
        st.paragraph_format.line_spacing = 1.15
        sec = self.doc.sections[0]
        sec.page_width, sec.page_height = Cm(21), Cm(29.7)
        sec.left_margin = sec.right_margin = Cm(2.5)
        sec.top_margin, sec.bottom_margin = Cm(2), Cm(2)

    def p(self, parts, align=WD_ALIGN_PARAGRAPH.JUSTIFY, space_after=6, size=None):
        """parts: stringhe oppure tuple (stile, testo); stili: b, i, ph (segnaposto), mono."""
        par = self.doc.add_paragraph()
        par.alignment = align
        par.paragraph_format.space_after = Pt(space_after)
        for part in ([parts] if isinstance(parts, (str, tuple)) else parts):
            style, text = ("", part) if isinstance(part, str) else part
            r = par.add_run(text)
            if size:
                r.font.size = Pt(size)
            if "b" in style.split("+"):
                r.bold = True
            if "i" in style.split("+"):
                r.italic = True
            if "ph" in style.split("+"):
                r.font.highlight_color = WD_COLOR_INDEX.YELLOW
            if "mono" in style.split("+"):
                r.font.name = "Consolas"
                r.font.size = Pt(9.5)
        return par

    def heading(self, text):
        par = self.p([("b", text)], align=WD_ALIGN_PARAGRAPH.LEFT, space_after=4)
        par.paragraph_format.space_before = Pt(10)
        par.paragraph_format.keep_with_next = True
        return par

    def bullet(self, parts):
        par = self.p(parts)
        par.paragraph_format.left_indent = Cm(0.8)
        par.paragraph_format.first_line_indent = Cm(-0.5)
        par.runs[0].text = "–\u00a0" + par.runs[0].text if par.runs else "–"
        return par

    def table(self, headers, rows, widths, size=10, header_bg="D9D9D9"):
        t = self.doc.add_table(rows=1, cols=len(headers))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, h in enumerate(headers):
            c = t.rows[0].cells[i]
            c.text = ""
            r = c.paragraphs[0].add_run(h)
            r.bold = True
            r.font.size = Pt(size)
            _set_cell_bg(c, header_bg)
        for row in rows:
            cells = t.add_row().cells
            for i, val in enumerate(row):
                cells[i].text = ""
                par = cells[i].paragraphs[0]
                par.paragraph_format.space_after = Pt(0)
                style, text = ("", val) if isinstance(val, str) else val
                r = par.add_run(text)
                r.font.size = Pt(size)
                if "ph" in style:
                    r.font.highlight_color = WD_COLOR_INDEX.YELLOW
                if "mono" in style:
                    r.font.name = "Consolas"
                    r.font.size = Pt(size - 1.5)
                if "b" in style:
                    r.bold = True
        t.autofit = False
        for i, gc in enumerate(t._tbl.tblGrid.findall(qn("w:gridCol"))):
            gc.set(qn("w:w"), str(int(Cm(widths[i]) / 635)))
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Cm(w)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)
        return t


def _v(value, placeholder):
    """Valore se presente, altrimenti segnaposto evidenziato."""
    value = (value or "").strip()
    return value if value else ("ph", placeholder)


def _rows(text, ncols):
    """Righe 'a | b | c' -> liste di ncols elementi."""
    out = []
    for line in (text or "").splitlines():
        if line.strip():
            parts = [x.strip() for x in line.split("|")]
            out.append((parts + [""] * ncols)[:ncols])
    return out


def _size(n):
    if n is None:
        return "-"
    for unit in ("byte", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}".replace(",", ".") if unit == "byte" else f"{n:.1f} {unit}".replace(".", ",")
        n /= 1024


# =========================================================================== verbale

def generate_verbale(case_dir, d, out_path=None):
    """Genera il verbale .docx nella cartella del caso e ne restituisce il percorso."""
    c = read_case(case_dir)
    m, pkg = c["m"], c["pkg"]
    w = Writer()
    doc = w.doc
    title, rif = TIPI_ATTO.get(d.get("tipo_atto"), TIPI_ATTO[GENERICO])
    pg = rif is not None                 # atto di polizia giudiziaria
    is_354 = pg and "354" in rif
    is_delega = pg and "370" in rif

    start = _loc(m["inizio_utc"])
    end = _loc(m["fine_utc"]) if m.get("fine_utc") else None
    operatori = _rows(d.get("operatori"), 3)
    presenti = [l.strip() for l in (d.get("presenti") or "").splitlines() if l.strip()]
    proc = (d.get("procedimento") or "").strip()
    plurale = len(operatori) != 1

    # ---- piè di pagina
    sec = doc.sections[0]
    fp = sec.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    lab = (f"Proc. pen. n. {proc} - " if pg else f"Rif. {proc} - ") if proc else ""
    r = fp.add_run(f"{lab}{title.capitalize()} - Pagina ")
    r.font.size = Pt(9)
    _field(fp, "PAGE", 9)
    r = fp.add_run(" di ")
    r.font.size = Pt(9)
    _field(fp, "NUMPAGES", 9)

    # ---- logo o stemma (facoltativo), centrato sopra l'intestazione
    stemma = Path(d.get("stemma_file") or "")
    if d.get("stemma_attivo") and stemma.is_file():
        try:
            larghezza = float(str(d.get("stemma_cm") or "1.8").replace(",", "."))
        except ValueError:
            larghezza = 1.8
        larghezza = min(max(larghezza, 0.8), 5.0)
        par = doc.add_paragraph()
        par.alignment = WD_ALIGN_PARAGRAPH.CENTER
        par.paragraph_format.space_after = Pt(4)
        par.add_run().add_picture(str(stemma), width=Cm(larghezza))

    # ---- intestazione: solo se indicata
    intest = [l for l in (d.get("intestazione") or "").splitlines() if l.strip()]
    for i, line in enumerate(intest):
        w.p([("b" if i == 0 else "", line.strip())], align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)
    if intest:
        w.p("", space_after=6)

    # ---- riferimenti: negli atti di polizia giudiziaria sempre, altrimenti solo se indicati
    if pg:
        w.p(["Procedimento penale n. ", ("b", proc) if proc else ("ph", "[numero] R.G.N.R.")],
            align=WD_ALIGN_PARAGRAPH.LEFT, space_after=0)
        w.p(["Autorità Giudiziaria: ", _v(d.get("autorita"), "[autorità giudiziaria procedente]")],
            align=WD_ALIGN_PARAGRAPH.LEFT, space_after=0)
        w.p(["Pubblico Ministero: ", _v(d.get("pm"), "[nome del magistrato]")],
            align=WD_ALIGN_PARAGRAPH.LEFT, space_after=12)
    else:
        refs = [("Riferimento: ", proc), ("Autorità o committente: ", (d.get("autorita") or "").strip())]
        refs = [(k, v) for k, v in refs if v]
        for i, (k, v) in enumerate(refs):
            w.p([k, ("b", v)], align=WD_ALIGN_PARAGRAPH.LEFT,
                space_after=12 if i == len(refs) - 1 else 0)

    w.p([("b", title)], align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0, size=13)
    w.p([("b", "di contenuti pubblicati sulla rete Internet" if not pg else
          "di acquisizione forense di contenuti pubblicati sulla rete Internet")],
        align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0 if rif else 12)
    if rif:
        w.p([("i", rif)], align=WD_ALIGN_PARAGRAPH.CENTER, space_after=12)

    # ---- apertura
    comune, presso = (d.get("comune") or "").strip(), (d.get("presso") or "").strip()
    luogo = ", ".join(x for x in (comune, presso) if x)
    w.p([f"Il giorno {start.day} {MESI[start.month - 1]} {start.year}, alle ore "
         f"{start.strftime('%H:%M')}, in ", luogo if luogo else ("ph", "[luogo]"), "."])
    if pg:
        w.p("Noi sottoscritti Ufficiali e Agenti di Polizia Giudiziaria:")
    else:
        w.p("I sottoscritti:" if plurale else "Il sottoscritto:")
    if operatori:
        for nome, qualifica, ente in operatori:
            w.bullet([", ".join(x for x in (nome, qualifica, ente) if x) + ";"])
    else:
        w.bullet([("ph", "[nome e cognome, qualifica, ente o organizzazione]")])
    if presenti:
        w.p("alla presenza di:")
        for x in presenti:
            w.bullet([x + ";"])

    if is_delega:
        w.p(["in esecuzione della delega di indagini emessa in data ",
             _v(d.get("data_delega"), "[data]"), " dal Pubblico Ministero ",
             _v(d.get("pm"), "[nome del magistrato]"),
             ", nell'ambito del procedimento penale sopra indicato,"])
    if pg:
        w.p([("b", "diamo atto di quanto segue.")])
    else:
        w.p([("b", "danno atto di quanto segue." if plurale else "dà atto di quanto segue.")])

    # ---- 1. oggetto
    w.heading("1. Oggetto e motivi dell'attività")
    w.p([_v(d.get("motivo"), "[Descrivere le ragioni dell'attività: incarico o richiesta "
                             "ricevuta, contenuti da documentare, ...]")])
    w.p(["L'attività ha per oggetto i contenuti accessibili all'indirizzo (URL): ",
         ("mono", m.get("url_partenza", ""))], align=WD_ALIGN_PARAGRAPH.LEFT)
    if is_354:
        w.p("Considerato il concreto pericolo che i dati in argomento vengano alterati, modificati "
            "o rimossi, anche dal titolare dello spazio web, e che il Pubblico Ministero non può "
            "intervenire tempestivamente ovvero non ha ancora assunto la direzione delle indagini, "
            "si procede agli accertamenti urgenti ai sensi dell'art. 354, comma 2, c.p.p., "
            "adottando le misure tecniche dirette ad assicurare la conservazione dei dati e a "
            "impedirne l'alterazione, con immediata duplicazione su adeguati supporti mediante "
            "procedura che assicura la conformità della copia all'originale e la sua immodificabilità.")

    # ---- 2. strumenti
    w.heading("2. Strumenti e postazione utilizzati")
    w.p("Le operazioni sono state eseguite con la postazione e gli strumenti di seguito indicati:")
    sistema = m.get("sistema", {})
    browser = m.get("browser", {})
    ntp = m.get("verifica_ntp", {})
    ntp_txt = (f"scostamento di {ntp['offset_secondi']} secondi rispetto al server {ntp['server']}"
               if "offset_secondi" in ntp else ("ph", "[verifica non riuscita: indicare il "
                                                     "riscontro effettuato]"))
    login = "autenticata" in (m.get("modalita") or "")
    rows = [
        ["Software di acquisizione", f"{m.get('strumento', '')}" +
         (f" (autore: {m['autore_strumento']})" if m.get("autore_strumento") else "") +
         (f", versione {m['distribuzione']}" if m.get("distribuzione") else "")],
        ["Impronta SHA-256 dell'eseguibile", ("mono", m["sha256_eseguibile"])
         if m.get("sha256_eseguibile") else "non disponibile (esecuzione da sorgente)"],
        ["Sistema operativo", sistema.get("os", "")],
        ["Nome della postazione", sistema.get("hostname", "")],
        ["Utente di sistema", sistema.get("utente_os", "")],
        ["Browser", browser.get("tipo", "Chromium")],
        ["User-Agent", ("mono", m.get("user_agent", ""))],
        ["Opzioni del browser", "aggiunte: " + ", ".join(browser.get("argomenti_aggiunti", []) or ["nessuna"])
         + "; rimosse: " + ", ".join(browser.get("argomenti_rimossi", []) or ["nessuna"])],
        ["Finestra del browser",
         (f"{browser['finestra'].get('modalita', '')}, area della pagina "
          f"{browser['finestra'].get('area_pagina', '')} pixel, schermo "
          f"{browser['finestra'].get('schermo', '')} pixel")
         if browser.get("finestra") else "dimensioni predefinite"],
        ["Indirizzo IP pubblico", m.get("ip_pubblico", "")],
        ["Verifica dell'orologio", ntp_txt],
        ["Modalità di accesso", m.get("modalita", "")],
        ["Piattaforma", m.get("piattaforma", "")],
    ]
    if login:
        rows.append(["Account utilizzato", _v(d.get("account"), "[account utilizzato]")])
    w.table(["Elemento", "Dettaglio"], rows, [5.0, 11.0])
    if browser.get("argomenti_aggiunti"):
        w.p("Le opzioni del browser sopra indicate riducono la riconoscibilità del browser come "
            "strumento automatizzato, al solo fine di consentire l'accesso ai contenuti, e non "
            "alterano il contenuto delle pagine visualizzate.")

    # ---- 3. operazioni
    w.heading("3. Descrizione delle operazioni")
    w.p(f"Alle ore {_ora(start)} del {_data(start)} si avviava la sessione di acquisizione, con "
        "registrazione integrale del traffico di rete (file HAR) e videoregistrazione della "
        "navigazione. Gli orari sono riferiti all'ora locale della postazione e sono documentati "
        "con precisione al millisecondo, in tempo coordinato universale (UTC), nel registro "
        "\"acquisizione.log\".")
    if login:
        w.p("L'accesso alla piattaforma avveniva mediante sessione autenticata preventivamente "
            "con l'account sopra indicato; la fase di autenticazione è stata eseguita separatamente "
            "e non è registrata, al fine di non riportare credenziali tra gli elementi acquisiti.")
    else:
        w.p("L'accesso avveniva con browser privo di cookie, cronologia e sessioni di "
            "autenticazione, a dimostrazione che i contenuti erano visibili a qualunque utente.")
    caps = {cap.get("n"): cap for cap in m.get("catture", [])}
    for t, kind, data in sorted(c["events"], key=lambda e: e[0]):
        if kind == "nav":
            w.bullet([f"alle ore {_ora(t)} si accedeva all'indirizzo ", ("mono", data), ";"])
        elif kind == "expand":
            w.bullet([f"alle ore {_ora(t)} si procedeva all'espansione automatica dei commenti, "
                      f"delle risposte e dei testi troncati ({data} interazioni, ciascuna "
                      "annotata nel registro), senza compiere alcuna azione modificativa dei "
                      "contenuti;"])
        elif kind == "capture":
            n, url, tit = data
            files = caps.get(n, {}).get("file", [])
            w.bullet([f"alle ore {_ora(t)} si cristallizzava lo stato della pagina "
                      f"(cattura n. {n}) avente titolo «{tit}», indirizzo ", ("mono", url),
                      f", acquisendo n. {len(files)} file: screenshot della porzione visibile e "
                      "dell'intera pagina, codice HTML, archivio MHTML e testo visibile;"])
        elif kind == "dialog":
            w.bullet([f"alle ore {_ora(t)} il sito presentava una finestra di dialogo, gestita "
                      "automaticamente come annotato nel registro;"])
        elif kind == "close":
            w.bullet([f"alle ore {_ora(t)} si chiudeva la sessione di navigazione."])
    n_caps = len(m.get("catture", []))
    w.p(f"Complessivamente sono state eseguite n. {n_caps} catture"
        + (f"; la sessione terminava alle ore {_ora(end)}." if end else "."))
    if d.get("note_operazioni", "").strip():
        w.p(d["note_operazioni"].strip())

    # ---- 4. impronte
    w.heading("4. Elementi acquisiti e impronte informatiche")
    w.p("Al termine, per ciascun file acquisito veniva calcolata l'impronta informatica (hash) con "
        "algoritmi SHA-256 e MD5, riportata nel file \"manifest.json\"; l'elenco dei file con le "
        "relative impronte SHA-256 è riportato nell'Allegato A al presente verbale. Tutti i file, "
        "unitamente ai registri, venivano raccolti nel pacchetto \"acquisizione.zip\", avente le "
        "seguenti impronte:")
    w.table(["Algoritmo", "Impronta del file acquisizione.zip"],
            [["SHA-256", ("mono", pkg["sha256"]) if pkg["sha256"] else ("ph", "[impronta]")],
             ["MD5", ("mono", pkg["md5"]) if pkg["md5"] else ("ph", "[impronta]")]], [3.0, 13.0])
    if pkg["tsa_time"]:
        tt = _loc(pkg["tsa_time"])
        w.p(["Il pacchetto veniva sottoposto a validazione temporale elettronica secondo lo "
             f"standard RFC 3161, rilasciata dal servizio {pkg['tsa_url'] or ''} con data e ora "
             f"certificate {_data(tt)}, ore {_ora(tt)} (numero di serie {pkg['tsa_serial']}), "
             "conservata nel file \"acquisizione.zip.tsr\". Trattandosi di validazione temporale "
             "non qualificata ai sensi del Regolamento (UE) n. 910/2014, ",
             ("ph", "[indicare l'eventuale ulteriore misura: marca temporale qualificata / "
                    "invio a mezzo PEC dell'impronta in data ...]"), "."])
    else:
        w.p(["Il pacchetto non è stato sottoposto a validazione temporale da parte del programma. ",
             ("ph", "[indicare l'eventuale misura alternativa adottata: marca temporale "
                    "qualificata / invio a mezzo PEC dell'impronta in data ...]")])

    # ---- 5. misure
    w.heading("5. Misure adottate per la conservazione e l'immodificabilità dei dati")
    w.p("Ai fini della conservazione dei dati e per impedirne l'alterazione, si dà atto che:")
    for x in [
        "l'attività è stata svolta limitandosi alla visualizzazione dei contenuti, senza "
        "inserimento di commenti, reazioni, messaggi o altre azioni modificative;",
        "ogni operazione è stata registrata automaticamente in un registro cronologico e nella "
        "videoregistrazione della sessione;",
        "il traffico di rete è stato integralmente registrato, consentendo di verificare la "
        "provenienza dei contenuti dai server del sito indicato;",
        "per ciascun file è stata calcolata l'impronta informatica e il pacchetto finale è stato "
        "chiuso con impronta propria, così che qualsiasi modifica successiva risulti rilevabile;",
        "la conformità di ogni copia all'originale è verificabile in qualsiasi momento mediante il "
        "confronto delle impronte, con strumenti standard indipendenti dal software utilizzato.",
    ]:
        w.bullet([x])

    # ---- 6. supporti
    w.heading("6. Supporti di memorizzazione")
    supporti = _rows(d.get("supporti"), 4)
    w.p("Il pacchetto \"acquisizione.zip\", unitamente ai file \"acquisizione.zip.sha256\", "
        "\"acquisizione.zip.tsq\", \"acquisizione.zip.tsr\" e \"chiusura.log\", veniva riversato sui "
        "seguenti supporti di memorizzazione, previa verifica della corrispondenza dell'impronta "
        "SHA-256 della copia con quella sopra riportata:")
    rows = [[str(i + 1)] + s for i, s in enumerate(supporti)] or \
        [["1", ("ph", "[tipo]"), ("ph", "[marca e modello]"), ("ph", "[n. di serie]"),
          ("ph", "[capacità]")]]
    w.table(["N.", "Tipo", "Marca e modello", "Numero di serie", "Capacità"], rows,
            [1.0, 3.5, 4.5, 4.5, 2.5])

    # ---- 7. custodia
    w.heading("7. Custodia")
    w.p([_v(d.get("custodia"), "[Indicare chi custodisce i supporti e dove]")])

    if d.get("note", "").strip():
        w.heading("8. Annotazioni")
        w.p(d["note"].strip())

    # ---- chiusura
    par = w.p(["Di quanto sopra si è redatto il presente verbale, composto da complessive n. "])
    _field(par, "NUMPAGES")
    par.add_run(" pagine, compreso l'Allegato A, che, previa lettura e conferma, viene chiuso alle "
                "ore ")
    rr = par.add_run("[__:__]")
    rr.font.highlight_color = WD_COLOR_INDEX.YELLOW
    firmatari = "dai verbalizzanti" if pg else ("dai sottoscritti" if plurale else "dal sottoscritto")
    par.add_run(f" del giorno {_data(dt.datetime.now())} e sottoscritto {firmatari}.")
    par.paragraph_format.space_before = Pt(10)

    intest_firme = "I VERBALIZZANTI" if pg else ("I SOTTOSCRITTI" if plurale else "IL SOTTOSCRITTO")
    w.p([("b", intest_firme)], align=WD_ALIGN_PARAGRAPH.RIGHT, space_after=6).paragraph_format.space_before = Pt(14)
    names = [n for n, _, _ in operatori if n] or ["[nome e cognome]"]
    for name in names:
        w.p([("ph", name) if name.startswith("[") else name], align=WD_ALIGN_PARAGRAPH.RIGHT,
            space_after=0)
        w.p("______________________________", align=WD_ALIGN_PARAGRAPH.RIGHT, space_after=14)
    if presenti:
        w.p([("b", "GLI ALTRI PRESENTI")], align=WD_ALIGN_PARAGRAPH.RIGHT, space_after=6)
        for x in presenti:
            w.p(x, align=WD_ALIGN_PARAGRAPH.RIGHT, space_after=0)
            w.p("______________________________", align=WD_ALIGN_PARAGRAPH.RIGHT, space_after=14)

    # ---- allegato A
    w.p([("b", "ALLEGATO A")], align=WD_ALIGN_PARAGRAPH.CENTER,
        space_after=0).paragraph_format.page_break_before = True
    w.p([("b", "Elenco dei file acquisiti e relative impronte SHA-256")],
        align=WD_ALIGN_PARAGRAPH.CENTER, space_after=4)
    w.p(f"Cartella di acquisizione: {c['dir'].name}\\acquisizione", align=WD_ALIGN_PARAGRAPH.CENTER,
        size=10, space_after=8)
    rows = [[str(i + 1), name, _size(size), ("mono", h)] for i, (name, size, h) in enumerate(c["files"])]
    w.table(["N.", "File", "Dimensione", "SHA-256"], rows or [["-", "-", "-", "-"]],
            [1.0, 5.5, 2.3, 7.2], size=9)

    # ---- salvataggio
    if out_path is None:
        base = c["dir"] / f"Verbale_{m.get('caso', 'acquisizione')}.docx"
        out_path, k = base, 2
        while out_path.exists():
            out_path = base.with_name(f"{base.stem}_{k}.docx")
            k += 1
    doc.save(out_path)
    return Path(out_path)
