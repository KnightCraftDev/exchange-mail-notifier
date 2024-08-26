# Changelog

Alle Änderungen an diesem Projekt werden in diesem Dokument festgehalten.

## 2024-08-26 [Unreleased]
### Added
- Added plugin support
- Added plugin to read Exchange tasks from the calendar.
- Added support for reading Exchange tasks from the calendar.
- Added configuration option to enable/disable reading Exchange tasks.
- Added configuration option to specify the number of days ahead to read Exchange tasks.


## [Unreleased]
### Hinzugefügt
- Schlüssel für die Passwortverschlüsselung wird weiterhin zufällig generiert (default) oder es wird ein fester Schlüssel auf Basis des Benutzernamens und Betriebssystems verwendet.
### Fixes
- Fehlerbehebung bei der Übernahme der Default-Einstellungen für die Konfiguration.

## [Unreleased]
### Hinzugefügt
- Erstellt die Grundstruktur der Anwendung `Exchange Mail Notifier`.
- Implementierung der Hauptfunktion `main()` zum Abrufen ungelesener E-Mails.
- Konfiguration von SSL und HTTP-Adapter zur Verbindung mit dem E-Mail-Server.
- Unterstützung für das Abrufen von E-Mails der letzten 1 bis 24 Stunden, konfigurierbar über `config.json`.
- Implementierung von sicherer Passwortverwaltung durch Verschlüsselung.
- GUI-Elemente zur Anzeige der Betreffzeilen ungelesener E-Mails mit `tkinter`.

### Verbesserungen
- Hinzugefügt: Möglichkeit zur Konfiguration mehrerer zusätzlicher Postfächer zur E-Mail-Abfrage.
- Überarbeitung der Zeitzonenvalidierung zur Unterstützung gängiger Zeitzonennamen.

### Fixes
- Erste Implementierung der Fehlerbehandlung zur Vermeidung von Abstürzen bei Verbindungsproblemen.
- Optimierung der Konfigurationseinstellungen zur Vermeidung von Benutzerfehlern.

### Dokumentation
- Erstellen von initialen README- und CHANGELOG-Dateien zur Dokumentation des Projekts.
- Hinzufügen von Beispielen für die `config.json`-Datei zur leichteren Konfiguration der Anwendung.

## [1.0.0] - 2024-08-06
- Veröffentlichung der ersten stabilen Version von `Exchange Mail Notifier`.
