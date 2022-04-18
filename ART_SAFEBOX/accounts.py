import time
from . import AESCipher

stay_duration = 20 * 60


class Account:
    def __init__(self, user_id):
        self.cipher = AESCipher.AESCipher()
        self.id = user_id

    def set_cookie_content(self, user_id, pwd):
        expire_time = time.time() + stay_duration
        cookie_content = {'uid': user_id, 'pwd': pwd, 'expire_time': expire_time}
        return self.cipher.encrypt(str(cookie_content))

    def isExpired(self, cookie_content):
        try:
            cookie_content = eval(self.cipher.decrypt(cookie_content))
            if cookie_content['uid'] == self.id:
                if cookie_content['expire_time'] >= time.time():
                    return False
            return True
        except:
            return True

    def update(self, cookie_content):
        try:
            cookie_content = eval(self.cipher.decrypt(cookie_content))
            if cookie_content['uid'] == self.id:
                cookie_content['expire_time'] = time.time() + stay_duration
                return self.cipher.encrypt(str(cookie_content))
            return None
        except:
            return None

    def get_priv_key(self, cookie_content):
        try:
            cookie_content = eval(self.cipher.decrypt(cookie_content))
            if cookie_content['uid'] == self.id:
                return cookie_content['pwd']
            return None
        except:
            return None


class OnlineAccounts:

    def __init__(self):
        self.online_accounts = dict()

    def add_online_account(self, account: Account):
        self.online_accounts.update({account.id: account})

    def remove_online_account(self, account: Account):
        if account.id in self.online_accounts:
            self.online_accounts.pop(account.id)
            del account

    def remove_online_account_by_id(self, user_id: str):
        account = self.get_online_account_by_id(user_id)
        if account is not None:
            self.remove_online_account(account)

    def get_online_account_by_id(self, user_id: str):
        if user_id in self.online_accounts:
            return self.online_accounts[user_id]
        else:
            return None

    def get_priv_key(self, user_id, cookie_content):
        account = self.get_online_account_by_id(user_id)
        if account is None:
            return None
        return account.get_priv_key(cookie_content)

    def check_login(self, user_id, cookie_content):
        account = self.get_online_account_by_id(user_id)
        if account is None or account.isExpired(cookie_content):
            del cookie_content
            return None
        cookie_content = account.update(cookie_content)
        return cookie_content


AccountManager = OnlineAccounts()
