# Web Forensic Extractor

[![Licenza: EUPL-1.2](https://img.shields.io/badge/licenza-EUPL--1.2-blue.svg)](LICENSE)
![Piattaforma: Windows](https://img.shields.io/badge/piattaforma-Windows%2010%20%7C%2011-informational)

Programma per Windows che acquisisce in modo forense pagine web e contenuti dei social network:
trasforma ciò che si vede nel browser in un insieme di file che si possono produrre come prova,
con tutto il necessario per dimostrarne l'integrità e la data di acquisizione.

## Cosa fa

- **Acquisizione di pagine pubbliche** con un browser pulito, senza cookie né sessioni, oppure
  **con login**, con sessioni salvate separatamente per ogni piattaforma. Il login si esegue in una
  fase non registrata, così le credenziali non finiscono nelle evidenze.
- Per ogni stato acquisito salva **screenshot** della parte visibile e dell'intera pagina,
  **HTML**, archivio **MHTML** e **testo**; per tutta la sessione registra il **traffico di rete**
  (HAR) e un **video** della navigazione.
- Alla chiusura calcola le impronte **SHA-256 e MD5** di ogni file, crea un pacchetto ZIP e richiede
  una **marca temporale RFC 3161**.
- **Espansione automatica** di commenti e risposte su Facebook, Instagram, X, LinkedIn, TikTok,
  YouTube e Reddit, senza mai cliccare pulsanti come Rispondi, Mi piace o Condividi.
- **Verbale delle operazioni** in Word, generico e utilizzabile da qualsiasi operatore, precompilato
  con cronologia, strumenti, impronte ed elenco dei file.
- **Archivio dei casi** con ricerca e verifica dell'integrità.
- Nessuna telemetria: tutti i dati restano sul computer dell'utente.

## Download

L'eseguibile pronto all'uso si scarica dalla pagina [Releases](../../releases): estrarre l'archivio
e avviare `WebForensicExtractor.exe`. Non serve installare nulla.

Requisiti: Windows 10 o 11 a 64 bit, connessione a internet, circa 1 GB di spazio libero.

## Documentazione

| Documento | Contenuto |
|---|---|
| [Guida operativa e valore legale](docs/Guida_Web_Forensic_Extractor.docx) | Uso del programma, pacchetto di acquisizione, verifica dell'integrità, quadro normativo |
| [Esempio di verbale](docs/Esempio_Verbale.docx) | Verbale generato da un'acquisizione di prova |
| [Pubblicazione sul Microsoft Store](docs/Guida_Pubblicazione_Microsoft_Store.docx) | Creazione del pacchetto MSIX e invio a Partner Center |
| [Informativa sulla privacy](docs/privacy.html) | Dati trattati dal programma e servizi esterni contattati |

## Compilare dal codice sorgente

Servono Windows 10/11 a 64 bit, [Python](https://www.python.org/) 3.10 o successivo a 64 bit
(installato con l'opzione «Add python.exe to PATH») e una connessione a internet.

| Script | Risultato |
|---|---|
| `build_windows.bat` | Versione portabile in `dist\WebForensicExtractor\` |
| `build_store.bat` | Pacchetto MSIX per il Microsoft Store in `dist_store\` (serve anche il Windows SDK; vedi la guida dedicata) |
| `prova_store.bat` | Installa o rimuove il pacchetto MSIX di prova (richiede la Modalità sviluppatore) |

Gli script creano un ambiente virtuale, installano le dipendenze (Playwright con Chromium,
python-docx, ttkbootstrap, asn1crypto, ntplib, PyInstaller) e producono l'eseguibile. Prima di una
nuova compilazione cancellare le cartelle `venv`, `build`, `dist`, `build_store` e `dist_store`.

L'icona originale della versione portabile e l'emblema della Repubblica non sono inclusi nel
repository (vedi [AVVISI.txt](AVVISI.txt)): in loro assenza la compilazione usa l'icona di
`store\icon.ico` e il verbale non propone lo stemma predefinito. Logo o stemma si possono comunque
inserire nel verbale con «Scegli immagine…».

## Struttura del repository

```
webacq_gui.py          programma principale (interfaccia, acquisizione, archivio)
verbale.py             generazione del verbale in Word
splash.png             schermata di avvio
build_windows.bat      compilazione della versione portabile
build_store.bat        compilazione del pacchetto per il Microsoft Store
prova_store.bat        prova locale del pacchetto Store
store/                 manifest MSIX, loghi, icona e testi per lo Store
docs/                  guide, verbale di esempio, informativa sulla privacy
LICENSE                licenza EUPL 1.2 (testo inglese)
LICENZA.txt            licenza EUPL 1.2 (testo italiano)
AVVISI.txt             diritti d'autore, elementi esclusi, componenti di terze parti
```

## Valore delle acquisizioni

Il programma documenta la procedura seguita: registri, impronte, traffico di rete e marca
temporale consentono a chiunque di verificare che il pacchetto non sia stato modificato. Il valore
probatorio di un'acquisizione resta però rimesso alla valutazione dell'autorità giudiziaria e
dipende anche da come l'operatore svolge l'attività. La guida operativa contiene un inquadramento
normativo e le buone pratiche da seguire.

## Licenza

Copyright © 2026 Giovanni Ciccarese.

Software libero concesso in licenza a norma della **Licenza Pubblica dell'Unione europea (EUPL)
v. 1.2** ([testo inglese](LICENSE), [testo italiano](LICENZA.txt)). Le versioni linguistiche
della licenza hanno identico valore. Il software è fornito «così com'è», senza garanzie.

L'eseguibile include componenti di terze parti distribuiti con le proprie licenze, elencati in
[AVVISI.txt](AVVISI.txt).

---

### English summary

Web Forensic Extractor is a Windows tool for the forensic capture of web pages and social media
content. It saves screenshots, HTML, MHTML, text, a HAR network log and a session video, seals
everything with SHA-256/MD5 hashes and an RFC 3161 timestamp, and generates an activity report
(in Italian) as a Word document. No telemetry; all data stays on the user's computer.
Licensed under the EUPL-1.2.
