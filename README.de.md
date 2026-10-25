# eMudhra CLI Trust Check

Technische Prüfhilfe von **Dzmitry Yablonski**, ergänzt durch **Stanislav Stolberg** um Windows-Unterstützung, robustere Diagnose und automatische Tests.

Das Werkzeug prüft, ob ausgewählte TLS-Clients betroffene eMudhra-Zertifikatsketten noch akzeptieren. Es liefert Befunde und Handlungshinweise für Security Professionals. Der **Check arbeitet lesend** und verändert keine Zertifikatsspeicher. Ein separater Windows-Updater aktualisiert ausdrücklich gewählte Anwendungen erst mit `-Apply`.

## Schnellstart

Das Repository über einen vertrauenswürdigen Kanal beziehen, entpacken und Terminal bzw. PowerShell **im Repository-Ordner** öffnen. Die Datei `SHA256SUMS` mit der im Browser angezeigten Fassung vergleichen. [Downloads und Hintergrund](README.md#how-to-run-it).

**macOS / Linux:**

```bash
shasum -a 256 -c SHA256SUMS
bash emudhra-cli-trust-check.sh
```

**Windows — PowerShell 5.1 oder 7:**

```powershell
Get-FileHash .\windows\*.ps1,.\windows\*.psm1 -Algorithm SHA256
.\windows\Test-Emudhra.ps1
```

Die ausgegebenen SHA-256-Werte mit `SHA256SUMS` vergleichen. Der Check benötigt keine Administratorrechte. Je nach Werkzeugen und Umgebungen dauert er mehrere Minuten. Betriebliche Anforderungen an Freigabe und signierte Skripte beachten; Ausführungsrichtlinien werden nicht geändert.

Optional unter macOS/Linux zusätzliche Python-Projektumgebungen und Hinweise auf deaktivierte TLS-Verifikation suchen:

```bash
bash emudhra-cli-trust-check.sh --scan "/pfad/zum/projekt"
bash emudhra-cli-trust-check.sh --help
```

`--scan` ist mehrfach möglich; Virtualenvs werden bis Tiefe 6 gesucht. Treffer zeigen nur Dateiname und Zeile. Ausgaben können lokale Pfade und Softwareversionen enthalten; vor dem Teilen prüfen. Die Skriptausgabe bleibt zur gemeinsamen technischen Auswertung auf Englisch.

## Prüfumfang

| Plattform | Live-TLS-Tests | Weitere Prüfungen |
| --- | --- | --- |
| macOS / Linux | curl, Git, entdeckte Python-Interpreter, requests, Node, AWS CLI; Java mit Compiler | SHA-256 betroffener Wurzeln in gefundenen CA-Bundles einschließlich botocore; ausgewählte Laufzeit- und App-Versionen |
| Windows | Windows/.NET und `curl.exe` | Git, Node, uv und ausgewählte Desktop-Apps per Version |

Live-Tests kontaktieren vier öffentliche Incident-Testserver, `pypi.org` und beim Bash-Git-Test `github.com`. AWS-Anfragen sind unsigniert. Keine lokalen Prüfberichte werden hochgeladen. curl ignoriert `.curlrc`; Python folgt keinen HTTP-Weiterleitungen und sendet keine `.netrc`-Zugangsdaten. Git übernimmt gezielt TLS-/Proxy-Einstellungen und unterdrückt Website-Authentifizierung, Cookies und URL-Umschreibungen. Proxy-/CA-Umgebungsvariablen gelten weiterhin; Windows/.NET verbindet direkt. Proxyfilter können die Aussagekraft beeinflussen.

## Windows-Anwendungen aktualisieren

WinGet muss verfügbar sein. Zuerst den Plan prüfen, anschließend dieselbe Auswahl anwenden:

```powershell
.\windows\Update-EmudhraWindows.ps1 -PackageId Git.Git,Microsoft.VisualStudioCode
.\windows\Update-EmudhraWindows.ps1 -PackageId Git.Git,Microsoft.VisualStudioCode -Apply
.\windows\Test-Emudhra.ps1
```

`-Apply -WhatIf` simuliert den Start; `-Help` zeigt unterstützte Paket-IDs. Nur ausgewählte, bereits installierte Pakete werden aktualisiert. Updates können Abhängigkeiten und Majorversionen ändern oder Installationsdialoge anzeigen. Windows selbst über Windows Update bzw. den zentralen Unternehmenskanal pflegen. Die Skripte ändern keine Windows-Zertifikatsspeicher. [WinGet-Dokumentation](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade).

## Ergebnisse

| Status | Bedeutung |
| --- | --- |
| `OK` | Jeweilige Prüfung bestanden; bei TLS: alle vier Ketten abgelehnt und Kontrollserver erreichbar |
| `VERSION_OK` | Versionsabgleich bestanden; kein Live-TLS-Nachweis für diese Anwendung |
| `VULNERABLE` | Betroffene Kette akzeptiert oder problematische CA im geprüften Bundle vorhanden |
| `OUTDATED` | Veraltet oder manuell zu prüfen |
| `INCONCLUSIVE` / `BROKEN` | Unvollständig bzw. nicht ausführbar; Ursache prüfen und erneut starten |

**Check-Exit-Codes:** `0` bestanden, `1` verwundbar, `2` Aufruffehler, `3` unvollständig/defekt, `4` veraltet oder Review nötig. Verwundbare Befunde haben Vorrang. Gegenüber 7.0.0 liefern auch unvollständige und veraltet-only Prüfungen einen Fehlercode.

**Updater-Exit-Codes:** `0` Plan/Simulation bzw. ausgewählte Updates abgeschlossen, `2` Aufruffehler, `3` Updatefehler, `4` kein anwendbares Update. Der letzte Fall beweist keinen Schutz: WinGet-Ausgabe prüfen und Check wiederholen.

## Grenzen und gemeinsame Pflege

Gezielte TLS-Diagnose; kein Nachweis, dass ein Rechner frei von Kompromittierung ist. Browser, Container und unabhängige Trust-Stores sind nicht vollständig abgedeckt. Unter Windows werden eigene Python-/Java-/AWS-CA-Bundles und Projektumgebungen nicht untersucht. Nach dem konservativen Ablaufdatum der Testzertifikate (**03.05.2027 UTC**) belegen Ablehnungen keinen Schutz mehr und werden als `INCONCLUSIVE` gewertet. Versionsstand: **24.10.2026**; vor späterer Nutzung abgleichen.

Änderungen als gezielte PRs in diesem Repository bündeln; Daten, Tests und englische/deutsche Anleitung gemeinsam aktualisieren. GitHub Actions prüft macOS, Linux und Windows mit PowerShell 5.1/7. Die lokalen TLS-Tests und simulierten Updater führen keine echten Anwendungsupdates aus. Die Entscheidung über Releases und Übernahme liegt bei den Repository-Maintainern. Für einen Einsatz bei OVB bleibt die interne Bewertung/Freigabe erforderlich.

Grundlagen: [Incident-Seite](https://emudhra.we-have-a-problem.com/), [Apple-Hinweise](https://support.apple.com/en-us/149555). [MIT-Lizenz](LICENSE); mit KI-Unterstützung überarbeitet und geprüft.
