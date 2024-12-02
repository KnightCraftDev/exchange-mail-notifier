#!/usr/bin/env python3

# Copyright (c) 2024, Mike - KnightCraftDev

# MIT License

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import getpass
import json
import os
import ssl
import sys
import urllib3
import tkinter as tk
import pystray
import pytz
import argparse
import platform
import base64
import hashlib
import importlib
import os
import tkinter.font as tkFont
import re

# Import the PluginInterface class from the plugin_interface.py file
from plugin_interface import PluginInterface
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from exchangelib import Credentials, Account, DELEGATE, Configuration, NTLM
from cryptography.fernet import Fernet
from tkinter import messagebox
from datetime import datetime, timedelta
from exchangelib.errors import UnauthorizedError
from collections import defaultdict

cert_file = None
ssl_context = None
# 10 Sekunden in Millisekunden (wird von config.json überschrieben)
timerWindowsClose = 10000
# E-Mails der letzten 18 Stunden abrufen (wird von config.json überschrieben)
# Zeitraum in Stunden (1-24; wird von config.json überschrieben)
numbersLastHours = 18
showAlways = True  # Fenster immer anzeigen; auch wenn keine E-Mails vorhanden sind
hideSSLWarning = False  # SSL-Warnung deaktivieren (nur für Entwicklungszwecke)
# Zufälligen Schlüssel generieren (True) oder Benutzerspezifischen Schlüssel verwenden (False)
randomSecretKey = True

# Automatisches Löschen der Passwortdatei, wenn ein Fehler auftritt
autodelete_password_file = True

config = []
# Zugriff auf die zusätzlichen Postfächer
additional_accounts = []
timeZone = "Europe/Berlin"


def is_valid_color_code(color):
    """
    Überprüft, ob der gegebene Farbcode gültig ist.
    Diese Funktion überprüft, ob der übergebene Farbcode entweder ein gültiger
    hexadezimaler Farbcode (3 oder 6 Stellen) oder ein bekannter Farbname ist.
    Args:
        color (str): Der zu überprüfende Farbcode oder Farbname.
    Returns:
        bool: True, wenn der Farbcode gültig ist, andernfalls False.
    """
    # Regex für hexadezimale Farbwerte (3 oder 6 Stellen)
    hex_color_pattern = r'^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'

    # Liste bekannter Farbnamen
    known_colors = {
        "black", "white", "red", "green", "blue", "yellow", "cyan", "magenta",
        "gray", "grey", "purple", "pink", "orange", "brown", "navy", "teal",
        # Weitere Farben können hinzugefügt werden
    }

    # Überprüfen, ob der Input ein hexadezimaler Farbcode ist
    if re.match(hex_color_pattern, color):
        return True

    # Überprüfen, ob der Input ein bekannter Farbname ist
    if color in known_colors:
        return True

    # Wenn keine der Bedingungen erfüllt ist
    return False


class CustomHTTPAdapter(NoVerifyHTTPAdapter):
    # BaseProtocol so konfigurieren, dass es den benutzerdefinierten SSL-Kontext verwendet
    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = ssl_context
        return super().init_poolmanager(*args, **kwargs)


class NoVerifySSLContext(ssl.SSLContext):
    # SSL-Verifizierung deaktivieren (nur für Entwicklungszwecke)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.verify_mode = ssl.CERT_NONE


def readExchangeMails():
    """
    readExchangeMails function that retrieves unread emails and displays their subject lines.

    This function performs the following steps:
    1. Loads configuration data from the 'config.json' file.
    2. Sets up SSL context and HTTP adapter based on the presence of a certificate file.
    3. Prompts for the password or reads it from the 'password.enc' file.
    4. Retrieves additional mailbox information if available.
    5. Checks the specified timezone and sets it as the default if valid.
    6. Authenticates with the email server using the provided credentials.
    7. Retrieves unread emails from the primary mailbox and additional mailboxes.
    8. Prints the subject lines of the unread emails.

    Args:
        None

    Returns:
        None
    """
    global config, cert_file, ssl_context, timerWindowsClose, randomSecretKey, numbersLastHours, showAlways, hideSSLWarning, additional_accounts, timeZone, autodelete_password_file

    # Authentifizierung
    credentials = Credentials(
        username=config['username'], password=config['password'])
    exchange_config = Configuration(
        server=config['server'],
        credentials=credentials,
        auth_type=NTLM
    )

    # Zugriff auf das Postfach
    try:
        account = Account(
            primary_smtp_address=config['email'],
            config=exchange_config,
            autodiscover=False,
            access_type=DELEGATE
        )
    except UnauthorizedError:
        print("Fehler: Ungültige Anmeldedaten. Das geheime Passwort wurde gelöscht (password.enc und secret.key).")

        if autodelete_password_file == True:
            # Lösche die Datei, wenn ein Fehler auftritt
            if os.path.exists("password.enc"):
                os.remove("password.enc")
            # Lösche Secret.key, wenn ein Fehler auftritt
            if os.path.exists("secret.key"):
                os.remove("secret.key")
        sys.exit(1)  # Programm beenden
    except Exception as e:
        print(f"Ein Fehler ist aufgetreten: {e}")
        sys.exit(1)  # Programm beenden

    # Zeitzone festlegen
    berlin_tz = pytz.timezone(timeZone)
    # Aktuellen Zeitpunkt und den Zeitpunkt vor 1-24 Stunden erhalten
    now = datetime.now(berlin_tz)
    last_hours = now - timedelta(hours=numbersLastHours)

    try:
        # Suche nach ungelesenen E-Mails der letzten Stunden im Posteingang
        inbox = account.inbox.filter(
            is_read=False,
            datetime_received__range=(last_hours, now)
        )
        unread_count = inbox.count()
        unread_emails = list(inbox)
        # unread_count = len(unread_emails)

        # Suche nach ungelesenen E-Mails der letzten 18 Stunden in den zusätzlichen Postfächern
        # und füge sie zur Liste der ungelesenen E-Mails hinzu
        for additional_mailbox in additional_accounts:
            print(f"Postfach: {additional_mailbox}")
            print(f"Zugriff auf Postfach: {account.primary_smtp_address}")
            additional_account = Account(
                primary_smtp_address=additional_mailbox,
                config=exchange_config,
                autodiscover=False,
                access_type=DELEGATE
            )
            additional_inbox = additional_account.inbox.filter(
                is_read=False,
                datetime_received__range=(last_hours, now)
            )
            unread_emails += list(additional_inbox)
            unread_count += additional_inbox.count()

        # Ausgabe der Betreffzeilen der neuen E-Mails
        for item in unread_emails:
            # Prüfen ob der Absender vorhanden ist
            if item.to_recipients is None:
                recipients = "Kein Absender"
            else:
                recipients = ", ".join(
                    [recipient.email_address for recipient in item.to_recipients]) if item.to_recipients else "Keine Empfänger"
            print(f"[{recipients}] {item.sender.name} {item.subject}")
    except Exception as e:
        print(f"Ein Fehler ist aufgetreten: {e}")
        sys.exit(1)  # Programm beenden

    return unread_emails, unread_count


def load_key(random_key=True):
    """
    Load the encryption key from a file or generate a new one.

    Args:
        random_key (bool, optional): Whether to generate a new key if one doesn't exist.
            Defaults to True.

    Returns:
        bytes: The encryption key.

    Raises:
        FileNotFoundError: If `random_key` is False and the key file doesn't exist.

    """
    if not random_key:
        return generate_user_specific_key()

    if os.path.exists("secret.key"):
        return open("secret.key", "rb").read()
    else:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key


def generate_user_specific_key():
    """
    Generates a user-specific key based on the current username and system information.

    Returns:
        bytes: The generated key as bytes.
    """
    # Abfrage des aktuellen Benutzernamens
    username = os.getlogin()

    # Abrufen einiger systembezogener Informationen
    system_info = platform.node() + platform.system() + platform.release() + \
        platform.machine() + platform.processor()

    # Kombinieren Sie Benutzernamen und Systeminformationen
    unique_string = username + system_info

    # Erstellen eines SHA-256-Hashes der eindeutigen Zeichenfolge
    hash_object = hashlib.sha256(unique_string.encode())
    hash_digest = hash_object.digest()

    # Verwenden der ersten 32 Bytes des Hashes, um einen Fernet-Schlüssel zu erstellen
    key = base64.urlsafe_b64encode(hash_digest[:32])

    return key


def adjust_text_height(text_widget):
    """
    Passt die Höhe eines Text-Widgets basierend auf der Anzahl der Zeilen und deren Höhe an.
    Args:
        text_widget (tk.Text): Das Text-Widget, dessen Höhe angepasst werden soll.
    Returns:
        int: Die berechnete Gesamthöhe des Text-Widgets in Pixeln.
    """
    # Erhalte die aktuelle Anzahl der Zeilen im Text
    line_count = int(text_widget.index('end-1c').split('.')[0])

    # Bestimme die Schriftart und -größe
    font = tkFont.Font(font=text_widget.cget("font"))
    line_height = font.metrics('linespace')  # Höheneinheit für die Schrift

    total_height = 0

    # Bestimme die Linienhöhe jeder einzelnen Zeile
    for i in range(1, line_count + 1):
        line_info = text_widget.dlineinfo(f"{i}.0")
        if line_info:
            line_height = line_info[3]  # Höhe der Zeile in Pixeln
            total_height += line_height
            # print(f"Zeilenhöhe von Zeile {i}: {line_height}")

    # Faktor für die Gesamthöhe
    total_height = int(total_height * line_count / 1.5)
    # print(f"Anzahl der Zeilen: {line_count}; Gesamthöhe: {total_height}")
    # Passen Sie die Höhe des Text-Widgets an
    text_widget.config(height=total_height)
    return total_height


def show_email_list(unread_emails, timerWindowsClose=5000):
    """
    Displays a list of unread emails in a tkinter window.

    Args:
        unread_emails (list): A list of email objects representing unread emails.
        timerWindowsClose (int, optional): The time in milliseconds after which the window should close. Defaults to 5000.
    """
    global config
    root = tk.Tk()
    root.title("Benachrichtigung: Neue E-Mails und Termine")
    root.attributes('-topmost', True)  # Fenster immer im Vordergrund

    # Fenster oben rechts auf dem primären Display positionieren
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = 500
    window_height = 50
    x = screen_width - window_width
    y = 0
    root.geometry(f'{window_width}x{window_height}+{x}+{y}')

    # Passe die Hintergrundfarbe dem Windows 10 Stil an
    # Helle Hintergrundfarbe, ähnlich wie Windows 10
    # root.configure(bg='#F0F0F0')
    root.configure(bg=config['windowBackground'])

    # Prüfen ob Icons im Unterordner ./assets vorhanden sind
    small_icon = None
    large_icon = None
    if os.path.exists("assets/icon-16.png"):
        small_icon = tk.PhotoImage(file="assets/icon-16.png")

    if os.path.exists("assets/icon-32.png"):
        large_icon = tk.PhotoImage(file="assets/icon-32.png")

    if large_icon is not None and small_icon is not None:
        root.iconphoto(False, large_icon, small_icon)

    # Scrollbar hinzufügen
    # scrollbar = tk.Scrollbar(root)
    # scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Text-Widget hinzufügen
    # text_widget = tk.Text(root, wrap=tk.WORD, yscrollcommand=scrollbar.set)
    # text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Fett-Schriftstil definieren
    # text_widget.tag_configure('bold', font=('Helvetica', 12, 'bold'))
    # Text-Widget hinzufügen
    text_widget = tk.Text(
        root, wrap=tk.WORD, bg=config['windowBackground'], fg=config['windowForeground'])
    text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Fett-Schriftstil definieren
    text_widget.tag_configure('bold', font=(
        'Helvetica', 12, 'bold'), foreground=config['windowForeground'])
    text_widget.tag_configure('normal', foreground=config['windowForeground'])

    # Prüfen ob E-Mails vorhanden sind
    if len(unread_emails) == 0:
        text_widget.insert(tk.END, "Keine neuen E-Mails vorhanden.", 'bold')
    else:
        # Dictionary zum Gruppieren der E-Mails nach Empfänger
        emails_by_recipient = defaultdict(list)
        # E-Mails nach Empfänger gruppieren
        for email in unread_emails:
            # Prüfen, ob email.to_recipients existiert
            if hasattr(email, 'to_recipients') and email.to_recipients:
                for recipient in email.to_recipients:
                    emails_by_recipient[recipient.email_address].append(email)
            else:
                emails_by_recipient["Keine Empfänger"].append(email)

        # Ausgabe der gruppierten E-Mails
        for recipient, emails in emails_by_recipient.items():
            text_widget.insert(tk.END, f"Empfänger: {recipient}\n", 'bold')
            for email in emails:
                text_widget.insert(tk.END, f"  {email.sender.name} ", 'bold')
                text_widget.insert(tk.END, f"{email.subject}\n", 'normal')

    # listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # scrollbar.config(command=listbox.yview)

    # Fenster nach X Sekunden schließen
    # root.after(timerWindowsClose, root.destroy)

    # root.mainloop()

    # Dynamische Anpassung der Fensterhöhe basierend auf der Höhe des Text-Widgets
    root.update_idletasks()
    _height = adjust_text_height(text_widget)
    # text_widget_height = text_widget.winfo_reqheight()
    text_widget_height = _height  # text_widget.winfo_height()
    # print(f"Text-Widget-Höhe: {text_widget_height}")
    window_height = max(window_height, text_widget_height)
    # print(window_height)
    root.geometry(f'{window_width}x{window_height}+{x}+{y}')

    # Fenster nach X Sekunden schließen
    root.after(timerWindowsClose, root.destroy)

    root.mainloop()


def check_timezone(nameTimeZone):
    """
    Check if the given timezone is valid.

    Args:
        nameTimeZone (str): The name of the timezone to check.

    Returns:
        bool: True if the timezone is valid, False otherwise.
    """
    try:
        pytz.timezone(nameTimeZone)
        return True
    except pytz.exceptions.UnknownTimeZoneError:
        return False


def read_config():
    """
    Read the configuration from the 'config.json' file.

    Returns:
        dict: The configuration data as a dictionary.
    """

    global config, cert_file, ssl_context, timerWindowsClose, randomSecretKey, numbersLastHours, showAlways, hideSSLWarning, additional_accounts, timeZone, autodelete_password_file
    # ----------------------
    # Einstellungen aus Datei laden und prüfen
    # ----------------------

    # Lade die Konfigurationsdaten
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)

     # Prüfen ob ein zufälliger Schlüssel generiert werden soll
    if 'randomSecretKey' in config:
        randomSecretKey_value = config['randomSecretKey']
        if isinstance(randomSecretKey_value, str):
            randomSecretKey_value = randomSecretKey_value.lower()
        if randomSecretKey_value in [False, 0, "false", None]:
            randomSecretKey = False
        else:
            randomSecretKey = True

    # Prüfen ob Passwortdatei automatisch gelöscht werden soll
    if 'autodelete_password_file' in config:
        autodelete_password_file_value = config['autodelete_password_file']
        if isinstance(autodelete_password_file_value, str):
            autodelete_password_file_value = autodelete_password_file_value.lower()
        if autodelete_password_file_value in [False, 0, "false"]:
            autodelete_password_file = False
        else:
            autodelete_password_file = True

    # Verschlüsselungsschlüssel laden
    key = load_key(randomSecretKey)
    cipher_suite = Fernet(key)

    # Prüfen ob der Benutzername vorhanden ist
    if 'username' not in config:
        print("Der Benutzername wurde nicht gefunden.")
        sys.exit(1)

    # Prüfen nach welcher Zeit das Fenster geschlossen werden soll
    if 'timerWindowsClose' in config:
        timerWindowsClose = config['timerWindowsClose']

    # Prüfen wie viele Stunden zurückgegangen werden soll, um E-Mails abzurufen
    # Ganzzahlwert zwischen 1-24 wird erwartet
    if 'numbersLastHours' in config:
        numbersLastHours = config['numbersLastHours']
        if numbersLastHours < 1 or numbersLastHours > 24:
            print("Die Anzahl der Stunden muss zwischen 1 und 24 liegen.")
            sys.exit(1)

    # Prüfen ob das Zertifikat vorhanden ist
    if os.path.exists(config['certfile']):
        # Pfad zum selbstsignierten Zertifikat
        cert_file = os.path.join(os.path.dirname(__file__), config['certfile'])
        # SSL-Kontext mit dem selbstsignierten Zertifikat erstellen
        ssl_context = ssl.create_default_context(cafile=cert_file)

        BaseProtocol.HTTP_ADAPTER_CLS = CustomHTTPAdapter
    else:
        print(
            "Das Zertifikat wurde nicht gefunden. Die SSL-Verifizierung wird deaktiviert.")
        BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter

    try:
        # Passwort sicher abfragen oder aus der Datei lesen
        if os.path.exists("password.enc"):
            with open("password.enc", "rb") as password_file:
                encrypted_password = password_file.read()
            config['password'] = cipher_suite.decrypt(
                encrypted_password).decode()
        else:
            config['password'] = getpass.getpass(
                'Bitte geben Sie Ihr Passwort ein: ')
            encrypted_password = cipher_suite.encrypt(
                config['password'].encode())
            with open("password.enc", "wb") as password_file:
                password_file.write(encrypted_password)
    except Exception as e:
        print(f"Ein Fehler ist aufgetreten: {e}")
        print("Das Passwort konnte nicht gelesen/gespeichert werden.")

        if autodelete_password_file == True:
            # Lösche die Datei, wenn ein Fehler auftritt
            if os.path.exists("password.enc"):
                os.remove("password.enc")
            # Lösche Secret.key, wenn ein Fehler auftritt
                if os.path.exists("secret.key"):
                    os.remove("secret.key")
        sys.exit(1)  # Programm beenden

    # Prüfen ob zusätzliche Postfächer vorhanden sind und diese hinzufügen
    if 'additional_mailboxes' in config:
        # Liste der zusätzlichen Postfächer
        additional_accounts = config['additional_mailboxes']
        if not isinstance(additional_accounts, list):
            print("Die zusätzlichen Postfächer müssen als Liste angegeben werden.")
            additional_accounts = []

    # Prüfen ob die Zeitzone korrekt ist
    if 'timeZone' in config:
        if not check_timezone(config['timeZone']):
            print(
                f"Die angegebene Zeitzone ist ungültig. Verwende die Standardzeitzone: {timeZone}")
        else:
            print(f"Zeitzone: {config['timeZone']}")
            timeZone = config['timeZone']

    # Prüfen ob das Fenster immer angezeigt werden soll
    if 'showAlways' in config:
        showAlways_value = config['showAlways']
        if isinstance(showAlways_value, str):
            showAlways_value = showAlways_value.lower()
        if showAlways_value in [False, 0, "false", None]:
            showAlways = False
        else:
            showAlways = True

    # Prüfen ob die SSL-Warnung ausgeblendet werden soll
    if 'hideSSLWarning' in config:
        hideSSLWarning_value = config['hideSSLWarning']
        if isinstance(hideSSLWarning_value, str):
            hideSSLWarning_value = hideSSLWarning_value.lower()
        if hideSSLWarning_value in [True, 1, "true"]:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Prüfen, ob windowBackground eine valiede Farbe ist
    if 'windowBackground' in config:
        windowBackground = config['windowBackground']
        if not is_valid_color_code(windowBackground) or len(windowBackground) < 3:
            print("Die windowBackground-Farbe muss im Format '#RRGGBB' angegeben werden.")
            config['windowBackground'] = '#F0F0F0'

    # Prüfen, ob windowForeground eine valiede Farbe ist
    if 'windowForeground' in config:
        windowForeground = config['windowForeground']
        if not is_valid_color_code(windowForeground) or len(windowForeground) < 3:
            print("Die windowForeground-Farbe muss im Format '#RRGGBB' angegeben werden.")
            config['windowForeground'] = '#666'
    # ----------------------
    # Ende der Konfigurationsprüfung
    # ----------------------


def load_plugins():
    global config
    plugins = []
    for filename in os.listdir('plugins'):
        if filename.endswith('.py'):
            module_name = filename[:-3]  # Entferne die Dateiendung

            # Prüfen ob Modul aus config geladen werden soll
            if 'plugin_' + module_name in config:
                allow_plugin = config['plugin_' + module_name]

                if isinstance(allow_plugin, dict):
                    allow_plugin_enabled = allow_plugin.get('enabled', False)
                if allow_plugin_enabled not in [True, 1, "true"]:
                    continue
            else:
                # Plugin nicht in der Konfiguration gefunden
                continue

            print(f"Lade Plugin: {module_name}")
            module = importlib.import_module(f'plugins.{module_name}')
            for attr in dir(module):
                plugin_class = getattr(module, attr)
                if isinstance(plugin_class, type) and issubclass(plugin_class, PluginInterface):
                    plugins.append(plugin_class(config))

    return plugins


def main():
    global timerWindowsClose, numbersLastHours, showAlways
    global config, cert_file, ssl_context, timerWindowsClose, randomSecretKey, hideSSLWarning, additional_accounts, timeZone

    read_config()

    # E-Mails abrufen
    unread_emails, unread_count = readExchangeMails()
    print(f"Anzahl der neuen E-Mails: {unread_count}")

    # Plugins laden
    plugins = load_plugins()
    for plugin in plugins:
        # Nur ausführen, wenn das Plugin die PluginInterface-Klasse implementiert und nicht die Basisklasse ist
        if plugin.__class__ != PluginInterface and issubclass(plugin.__class__, PluginInterface):
            # print(f"Ausführung des Plugins: {plugin.__class__.__name__}")

            # E-Mails hinzufügen
            unread_emails, unread_count = plugin.add_emails(
                unread_emails, unread_count)

    # E-Mails anzeigen
    if showAlways or unread_count > 0:
        show_email_list(unread_emails, timerWindowsClose)
    else:
        print("Keine neuen E-Mails vorhanden.")


if __name__ == "__main__":
    # Beispiel für die config.json
    config_example = """
        Beispiel für config.json:
        {
            "username": "dein_benutzername",
            "server": "dein_exchange_server",
            "email": "deine_email@domain.com",
            "timerWindowsClose": 5000,
            "certfile": "cert.pem",
            "hideSSLWarning": false,
            "numbersLastHours": 18,
            "showAlways": true,
            "timeZone": "Europe/Berlin",
            "additional_mailboxes": [
                "zusatzpostfach1@example.com",
                "zusatzpostfach2@example.com"
            ],
            "randomSecretKey": true
        }
    """
    # ArgumentParser mit erweiterter Beschreibung
    parser = argparse.ArgumentParser(
        description=f"Prüfen des Exchange Postfach nach neuen und ungelesenen E-Mails. Anschließend ein Infofenster mit den E-Mails anzeigen.\n\n{config_example}\n\nPasswort für das Postfach wird nach ersten Start abgefragt und verschlüsselt in der Datei 'password.enc' gespeichert.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    args = parser.parse_args()

    # Prüfen ob die config.json vorhanden ist. Wenn nicht, dann Hilfe anzeigen
    if not os.path.exists("config.json"):
        print("Die Datei config.json wurde nicht gefunden.")
        print("Bitte erstellen Sie die Datei config.json mit den erforderlichen Einstellungen.")
        print(config_example)
        sys.exit(1)  # Programm beenden

    main()
