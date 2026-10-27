# -*- coding: utf-8 -*-

import os
import configparser

import alfred
import otp


class AlfredGAuth(alfred.AlfredWorkflow):
    _config_file_initial_content = """
#Examples of valid configurations:
#[google - bob@gmail.com]
#secret=xxxxxxxxxxxxxxxxxx
#
#[evernote - robert]
#secret=yyyyyyyyyyyyyyyyyy
"""

    _reserved_words = ['add', 'update', 'remove']

    _legacy_config_file = '~/.gauth'

    def __init__(self, config_file=None, max_results=20):
        self.max_results = max_results

        self.config_file = os.path.expanduser(config_file or self.find_config())
        self._config_file = self.config_file.replace(os.path.expanduser('~'), '~', 1)
        self.config = configparser.RawConfigParser()

        # If the configuration file doesn't exist, create an empty one
        if not os.path.isfile(self.config_file):
            self.create_config()

        try:
            self.config.read(self.config_file)
            self.config_error = None
        except configparser.Error as e:
            self.config_error = e

    @classmethod
    def find_config(cls):
        # Use the XDG config path, falling back to the original ~/.gauth if that's all there is
        config_home = os.environ.get('XDG_CONFIG_HOME') or '~/.config'
        config_file = os.path.join(os.path.expanduser(config_home), 'google-authenticator')
        legacy = os.path.expanduser(cls._legacy_config_file)
        if not os.path.exists(config_file) and os.path.exists(legacy):
            return legacy
        return config_file

    def create_config(self):
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        with open(self.config_file, 'w') as f:
            f.write(self._config_file_initial_content)
            f.close()

    def config_get_account_token(self, account):
        try:
            secret = self.config.get(account, 'secret')
        except:
            secret = None

        try:
            key = self.config.get(account, 'key')
        except:
            key = None

        try:
            hexkey = self.config.get(account, 'hexkey')
        except:
            hexkey = None

        try:
            key = otp.get_hotp_key(secret=secret, key=key, hexkey=hexkey)
        except:
            key = ''

        return otp.get_totp_token(key)

    def config_list_accounts(self):
        return self.config.sections()

    def filter_by_account(self, account, query):
        return len(query.strip()) and not query.lower() in str(account).lower()

    def account_item(self, account, token, uid=None):
        return alfred.Item({u'uid': alfred.get_uid(uid), u'arg': token,
                            u'autocomplete': account}, account,
                           token, 'icon.png')

    def config_file_is_empty_item(self):
        return self.warning_item(title='Google Authenticator is not yet configured',
                                 message='You must add your secrets to '
                                 'the {} file (see documentation)'
                                 .format(self._config_file))

    def search_by_account_iter(self, query):
        if self.is_command(query):
            return
        i = 0
        for account in self.config_list_accounts():
            if self.filter_by_account(account, query):
                continue
            token = self.config_get_account_token(account)
            entry = self.account_item(uid=i, account=account, token=token)
            if entry:
                yield entry
                i += 1
        if not i:
            yield self.warning_item('Account not found',
                                    'There is no account matching "{}" '
                                    'in your config file '
                                    '({})'.format(query,
                                                  self._config_file))

    def add_account(self, account, secret):
        if not otp.is_otp_secret_valid(secret):
            return "Invalid secret:\n[{0}]".format(secret)

        try:
            self.config.add_section(account)
        except configparser.DuplicateSectionError:
            return "Account already exists:\n[{0}]".format(account)

        self.config.set(account, "secret", secret)
        with open(self.config_file, 'w') as config_file:
            self.config.write(config_file)

        return "A new account was added:\n[{0}]".format(account)

    def do_search_by_account(self, query):
        if self.config_error:
            self.write_item(self.exception_item(title='{}: Invalid syntax'
                                                .format(self._config_file),
                                                exception=self.config_error))
        elif not self.config.sections():
            # If the configuration file is empty,
            # tell the user to add secrets to it
            self.write_item(self.config_file_is_empty_item())
        else:
            self.write_items(self.search_by_account_iter(query))

    def do_add_account(self, query):
        try:
            account, secret = query.split(",", 1)
            account = account.strip()
            secret = secret.strip()
        except ValueError:
            return self.write_text('Invalid arguments!\n'
                                   'Please enter: account, secret.')

        if self.config_error:
            return self.write_text('{}: Invalid syntax'.format(self._config_file))

        return self.write_text(self.add_account(account, secret))


def main(action, query):
    alfred_gauth = AlfredGAuth()
    alfred_gauth.route_action(action, query)


if __name__ == "__main__":
    main(action=alfred.args()[0], query=alfred.args()[1])

