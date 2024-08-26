#!/usr/bin/env python3

# Copyright (c) 2024, Mike - KnightCraftDev

# PluginInterface mit den Methoden add_emails mit zwei Parametern
# unread_emails: Liste mit den ungelesenen Emails
class PluginInterface:
    def __init__(self, config):
        self.config = config  # Speichern der übergebenen Konfiguration

    def add_emails(self, email_list):
        raise NotImplementedError(
            "Plugins müssen die `add_emails()`-Methode implementieren.")
