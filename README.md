# Exchange Mail Notifier

**Exchange Mail Notifier** ist eine Python-Anwendung, die entwickelt wurde, um ungelesene E-Mails aus einem angegebenen Postfach abzurufen und deren Betreffzeilen in einem keinen Fenster anzuzeigen. Diese Anwendung ruft E-Mails basierend auf konfigurierbaren Parametern ab, einschließlich des Zeitrahmens für den Abruf von E-Mails und der Postfachdetails. Die Anwendung verwendet die `exchangelib`-Bibliothek, um eine Verbindung zu Exchange-Servern herzustellen und E-Mails abzurufen.
Nach Ablauf des Zeitrahmens wird das Fenster automatisch geschlossen, um die Benachrichtigung zu beenden.

## Funktionen

- Abrufen von ungelesenen E-Mails aus einem Hauptpostfach sowie zusätzlichen Postfächern (sofern konfiguriert).
- Konfigurierbarer Zeitraum zum Abrufen ungelesener E-Mails (von 1 bis 24 Stunden).
- Einfache und sichere Passwortverwaltung mithilfe von Verschlüsselung.
- Anzeige eines Fensters mit den Betreffzeilen ungelesener E-Mails.
- Kompatibel mit selbstsignierten SSL-Zertifikaten, mit Optionen, um die SSL-Verifizierung für Entwicklungszwecke zu deaktivieren.

## Installation

1. **Repository klonen**:
   ```sh
   git clone https://github.com/KnightCraftDev/exchange-mail-notifier.git
   cd exchange-mail-notifier
   ```

2. **Virtuelle Python-Umgebung einrichten** (optional, aber empfohlen):
   ```sh
   python3 -m venv venv
   source venv/bin/activate  # Verwende `venv\Scripts\activate` unter Windows
   ```

3. **Benötigte Pakete installieren**:
   Stelle sicher, dass `pip` installiert ist, und führe dann den folgenden Befehl aus:
   ```sh
   pip install -r requirements.txt
   ```

   Stelle sicher, dass du eine `requirements.txt`-Datei in deinem Projektverzeichnis erstellst, falls sie nicht bereits existiert. Füge die erforderlichen Bibliotheken hinzu:
   ```
   exchangelib
   cryptography
   pytz
   pystray
   ```

4. **Konfigurationsdatei erstellen**:
   Erstelle eine `config.json`-Datei im selben Verzeichnis mit folgendem Format:
   ```json
   {
       "username": "dein_benutzername", // Das zugehörige Passwort wird beim ersten Start der Anwendung eingegeben und verschlüsselt gespeichert
       "email": "deine_email@example.com",
       "server": "dein_email_server",
       "certfile": "pfad/zum/zertifikat.crt", // Optional, wenn du ein selbstsigniertes Zertifikat verwendest
       "hideSSLWarning": false, // Deaktiviere Warnungen zur SSL-Verifizierung (true/false)
       "timerWindowsClose": 10000, // Zeit in Millisekunden, bevor das Fenster automatisch geschlossen wird
       "numbersLastHours": 18, // Anzahl der Stunden, in denen ungelesene E-Mails abgerufen werden
       "showAlways": true, // Zeige das Fenster immer, auch wenn keine ungelesenen E-Mails vorhanden sind (true/false)
       "additional_mailboxes": [
            "zusatzpostfach1@example.com",
            "zusatzpostfach2@example.com"
        ], // Liste von zusätzlichen Postfächern, die abgerufen werden sollen
       "timeZone": "Europe/Berlin",
       "randomSecretKey": true // true = Generiere einen zufälligen Schlüssel für die Passwortverschlüsselung (default); false = Verwende einen festen Schlüssel auf Basis des Benutzernamens und Betriebssystems
   }
   ```

5. **Generiere einen geheimen Schlüssel**:
   Wenn die Anwendung zum ersten Mal ausgeführt wird, wird sie eine `secret.key`-Datei generieren, um die Passwortverschlüsselung zu verwalten.

## Verwendung

1. **Anwendung ausführen**:
   ```sh
   python main.py
   ```

2. **Gib dein Passwort ein**: Die Anwendung fordert dich auf, dein Passwort einzugeben. Dieses Passwort wird sicher verschlüsselt und in der Datei `password.enc` gespeichert.

3. **Ungelesene E-Mails anzeigen**: Nach einer erfolgreichen Verbindung zum Postfach werden alle ungelesenen E-Mails innerhalb des angegebenen Zeitrahmens in der grafischen Benutzeroberfläche angezeigt.

## Tipp

Erstelle eine Aufgabenplanung oder Cronjob, um die Anwendung automatisch alle 5 Minuten zu starten. Dies stellt sicher, dass keine ungelesenen E-Mails verpasst werden.

## Sicherheitshinweis

Diese Anwendung verwendet SSL, um sicher mit dem E-Mail-Server zu verbinden. Sie hat jedoch Optionen, um die SSL-Verifizierung während der Entwicklung zu deaktivieren. Stelle sicher, dass die SSL-Verifizierung in der Produktion aktiviert ist, um die Sicherheit aufrechtzuerhalten.

## Disclaimer

Diese Anwendung wurde für den persönlichen Gebrauch entwickelt und sollte nicht für kritische oder sicherheitsrelevante Anwendungen verwendet werden. Es wird empfohlen, die Anwendung in einer sicheren Umgebung zu testen und zu verwenden. Der Autor übernimmt keine Haftung für Schäden oder Verluste, die durch die Verwendung dieser Anwendung entstehen.

## Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert. Siehe die [LICENSE](LICENSE)-Datei für Details.

## Mitwirken

Beiträgen sind willkommen! Bitte forke dieses Repository und reiche einen Pull-Request für Änderungen oder Verbesserungen ein.

## Autor

Mike - KnightCraftDev

