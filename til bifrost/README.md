# wsiEKSPORT fuld-myndighed til Bifrost

Selvstændig version af wsiEKSPORT-klienten, beregnet til at blive flyttet til en server og køre skemalagt. Den henter **fuld-myndighed**-eksporten fra STIL for hver konfigureret institution og lægger XML-filerne i en fast mappe, som Bifrost kan læse fra.

Mappen kan kopieres som den er — den afhænger ikke af resten af projektet.

## Indhold

| Fil | Formål |
|---|---|
| `wsieksport_fuld_myndighed.py` | Klienten (WS-Security, eksport, verifikation af svar, atomisk skrivning) |
| `koer_eksport.bat` | Starter til Task Scheduler; kører uafhængigt af arbejdsmappe og returnerer scriptets exit-kode |
| `.env.example` | Skabelon til `.env` med al konfiguration |
| `requirements.txt` | Python-afhængigheder |
| `ca/` | OCES rod- og udstedende CA, bruges til at verificere STILs svar |

## Forudsætninger

- Windows-server med Python 3.12+ og adgang til internettet (udgående HTTPS til `brugerdatabasen.stil.dk`)
- OCES3-certifikat og ukrypteret privat nøgle tilknyttet udbydersystemet, samt udbydersystem-ID
- Godkendt dataaftale for fuld-myndighed for de ønskede institutioner

## Installation

Kopiér hele mappen til serveren og kør fra den (PowerShell):

```powershell
cd "D:\til bifrost"
py -3.12 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
copy .env.example .env
```

Udfyld derefter `.env` (se nedenfor). `.env` må ikke kopieres med fra udviklingsmaskinen — den indeholder stier, der er specifikke for hver maskine.

## Konfiguration (`.env`)

| Variabel | Påkrævet | Beskrivelse |
|---|---|---|
| `CERT_FILE` | ja | Sti til OCES3-certifikat (.cer, DER) |
| `KEY_FILE` | ja | Sti til privat nøgle (ukrypteret PKCS8) |
| `UDBYDER_SYSTEM_ID` | ja | Udbydersystem-ID hos STIL |
| `INSTITUTIONS` | ja | Kommasepareret liste af institutionsnumre |
| `OUTPUT_DIR` | ja | Mappen XML-filerne gemmes i. Oprettes hvis den mangler |
| `INKLUDER_CPR` | nej | `true` for at få CPR-numre med (STILs standard: udelades) |
| `KLASSETRIN` | nej | Begræns til klassetrin, fx `0,1,2,3` (gyldige: DT, 0-10, U1-U4, VU, Andet) |
| `AKTOERTYPER` | nej | Begræns til aktørtyper, fx `elever,medarbejdere` (gyldige: elever, medarbejdere, eksterne, kontaktpersoner) |
| `LOG_LEVEL` | nej | `DEBUG`, `INFO` (standard), `WARNING` eller `ERROR` |
| `LOG_FILE` | nej | Logfil (standard `wsieksport.log` i denne mappe) |

De tre valgfrie filtre er STILs [dataminimeringsfiltre](https://viden.stil.dk/spaces/INFRA2/pages/295109152/wsiEKSPORT+Dataminimeringsfiltre). Udelades de, bruges STILs standard.

Læg certifikat og nøgle uden for denne mappe, og begræns filadgangen til den konto, som schedulen kører som.

## Output

Én fil pr. institution i `OUTPUT_DIR`:

```
eksport_fuld-myndighed_101088.xml
eksport_fuld-myndighed_101155.xml
eksport_fuld-myndighed_101126.xml
```

- Filnavnene er faste, og filerne **overskrives** ved hver kørsel.
- Filerne skrives atomisk: først til en `.xml.tmp`-fil, som derefter omdøbes. Bifrost ser derfor aldrig en halvskrevet `.xml`-fil.
- Fejler hentningen for en institution, **efterlades den eksisterende fil urørt** (den seneste gode version bliver liggende), og de øvrige institutioner hentes stadig.

## Test manuelt

Kør først en gang i hånden, inden schedulen oprettes:

```powershell
cd "D:\til bifrost"
.\koer_eksport.bat            # alle institutioner fra .env
.\koer_eksport.bat 101088     # kun én institution (tilsidesætter INSTITUTIONS)
echo $LASTEXITCODE
```

Forventet log ved succes:

```
2026-09-23 05:00:01 INFO     Start: fuld-myndighed for 3 institution(er) → D:\bifrost\indbakke
2026-09-23 05:00:03 INFO     eksporterXmlFuldMyndighed      HTTP 200    1.23s  245 KB
2026-09-23 05:00:03 INFO     Gemt: D:\bifrost\indbakke\eksport_fuld-myndighed_101088.xml (312 KB)
...
2026-09-23 05:00:09 INFO     Færdig: alle 3 institution(er) hentet
```

## Opsæt schedule i Windows Task Scheduler

Vælg selv tidspunkt og hyppighed. Opgaven skal blot kalde `koer_eksport.bat`.

**Via kommandolinje** (kør som administrator; tidspunkt og konto er eksempler):

```powershell
schtasks /Create /TN "STIL wsiEKSPORT fuld-myndighed" `
  /TR "\"D:\til bifrost\koer_eksport.bat\"" `
  /SC DAILY /ST 05:00 `
  /RU "DOMÆNE\servicekonto" /RP *
```

**Anbefalede indstillinger** (Task Scheduler → opgavens egenskaber):

- *General*: **Run whether user is logged on or not**, kør som en dedikeret servicekonto med adgang til certifikat, nøgle, denne mappe og `OUTPUT_DIR`.
- *Settings*: **Do not start a new instance** hvis opgaven allerede kører, så to kørsler ikke overlapper.
- *Settings*: **Stop the task if it runs longer than** fx 1 time (forespørgslerne har selv en timeout på 10 minutter).
- *Settings*: evt. **If the task fails, restart every** 15 minutter, op til 3 gange — den skal fejle med exit-kode ≠ 0 for at udløse det.
- *Actions*: "Start in" behøver ikke udfyldes; `koer_eksport.bat` skifter selv til den rigtige mappe.

## Exit-koder og fejlfinding

| Exit-kode | Betydning |
|---|---|
| `0` | Alle institutioner hentet |
| `1` | Mindst én institution fejlede (se loggen; øvrige filer er stadig opdateret) |
| `2` | Konfigurationsfejl, fx manglende `.env`-værdi eller ukendt filterværdi |
| `3` | `.venv` mangler (fra `koer_eksport.bat`) |

Alt logges til konsollen og til `wsieksport.log` (roterer ved 1 MB, 5 filer gemmes). Sæt `LOG_LEVEL=DEBUG` for detaljer om certifikatkæde og signaturverifikation.

Typiske fejl:

- **HTTP 403/500 fra STIL** — tjek udbydersystem-ID, at certifikatet er tilknyttet udbydersystemet, og at der er en godkendt dataaftale for institutionen.
- **"certifikatet er udløbet"** — OCES3-certifikatet (eller STILs) er udløbet; fornyes hos MitID Erhverv, og `CERT_FILE`/`KEY_FILE` opdateres.
- **Ingen ny fil, ingen fejl** — tjek at opgaven faktisk kører som den rigtige konto og har skriveadgang til `OUTPUT_DIR`.

## Sikkerhed

- Certifikat og privat nøgle er legitimationen til STILs Brugerdatabase. Opbevar dem uden for denne mappe, med læseadgang kun for servicekontoen.
- Eksporten indeholder personoplysninger. Begræns adgangen til `OUTPUT_DIR` til servicekontoen og Bifrost, og overvej `KLASSETRIN`/`AKTOERTYPER`/`INKLUDER_CPR` for at hente mindst muligt.
- Under kald oprettes midlertidige PEM-filer med certifikat og nøgle i systemets temp-mappe, som slettes igen straks efter kaldet.
