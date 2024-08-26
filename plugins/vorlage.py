#!/usr/bin/env python3

# Copyright (c) 2024, Mike - KnightCraftDev

# plugins/vorlage.py

from plugin_interface import PluginInterface
import sys


class Sender:
    def __init__(self):
        self.name = None
        self.email = None


class EmailData:
    def __init__(self):
        self.sender = Sender()
        self.subject = ""
        self.body = ""


class PluginVorlage(PluginInterface):
    def __init__(self, config):
        super().__init__(config)  # Initialisierung der Basisklasse
        # Verwende die globale Variable

    def add_emails(self, unread_emails, unread_count):

        # Der unread_email weitere Einträge hinzufügen im Format .sender.name, .sender.email, .subject, .body

        # Definiere data als class
        data = EmailData()

        data.sender.name = "Mike"
        data.sender.email = "test@ll"
        data.subject = "Test"
        data.body = "Test"

        unread_emails.append(data)

        unread_count += 1

        # unread_email zurückgeben
        return unread_emails, unread_count


# Verhindern, dass das Plugin alleine ausgeführt wird
if __name__ == "__main__":
    print("Dieses Plugin kann nicht alleine ausgeführt werden. Bitte führen Sie das Hauptprogramm aus.")
    sys.exit(1)
