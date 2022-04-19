import sqlite3
import json
import base64
import io
import time
import traceback
import typing
import copy
import os

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

from PIL import Image
from django.db import connection


class DBmanager:
    # DATABASE_PATH = "./demo.db"
    COLLECTIONS_TABLE_NAME = "collections"
    USER_TABLE_NAME = "users"
    TRANSACTIONS_TABLE_NAME = "transactions"

    def __init__(self):
        # init connection, db will be created if it doesn't exist
        # self.conn = sqlite3.connect(self.DATABASE_PATH)
        # self.cur = self.conn.cursor()
        self.cur = connection.cursor()
        # init tables
        self.init_collections_table()
        self.init_user_table()
        self.init_transactions_table()

    # init tables

    def init_collections_table(self):
        if (
                len(
                    self.cur.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='{}';".format(
                            self.COLLECTIONS_TABLE_NAME
                        )
                    ).fetchall()
                )
                > 0
        ):
            print("Find '{}' table in db.".format(self.COLLECTIONS_TABLE_NAME))
            return
        # id | owner_id | price | encrypted_content | preview_path | status
        self.cur.execute(
            "CREATE TABLE '{}' "
            "(ID TEXT, OWNER_ID TEXT, PRICE REAL, ENCRYPTED_CONTENT BOLB, PREVIEW_PATH TEXT, STATUS TEXT);".format(
                self.COLLECTIONS_TABLE_NAME
            )
        )
        # self.conn.commit()
        print("Images table initialized.")

    def init_user_table(self):
        if (
                len(
                    self.cur.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='{}';".format(
                            self.USER_TABLE_NAME
                        )
                    ).fetchall()
                )
                > 0
        ):
            print("Find '{}' table in db.".format(self.USER_TABLE_NAME))
            return
        # id | validation_file | pub_key | balance
        self.cur.execute(
            "CREATE TABLE '{}' (ID TEXT, VALIDATION_FILE TEXT, PUB_KEY TEXT, BALANCE REAL);".format(
                self.USER_TABLE_NAME
            )
        )
        # self.conn.commit()
        print("Users table initialized.")

    def init_transactions_table(self):
        if (
                len(
                    self.cur.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='{}';".format(
                            self.TRANSACTIONS_TABLE_NAME
                        )
                    ).fetchall()
                )
                > 0
        ):
            print("Find '{}' table in db.".format(self.TRANSACTIONS_TABLE_NAME))
            return
        # id | timestamp | type | content | collection_id | src_user_id | dest_user_id | status
        self.cur.execute(
            "CREATE TABLE '{}' (\
                ID INTEGER PRIMARY KEY, \
                TIMESTAMP REAL, \
                TYPE TEXT, \
                CONTENT TEXT, \
                COLLECTION_ID TEXT, \
                SRC_USER_ID TEXT, \
                DEST_USER_ID TEXT, \
                STATUS TEXT, \
                AMOUNT REAL);".format(
                self.TRANSACTIONS_TABLE_NAME
            )
        )
        # self.conn.commit()
        print("Transaction table initialized.")

    # manage collections TABLE

    def add_collection(
            self,
            collection_id: str,
            price: typing.Union[float, None] = None,
            owner_id: typing.Union[str, None] = None,
            encrypted_content: typing.Union[str, None] = None,
            preview_path: typing.Union[str, None] = None,
            status: typing.Union[str, None] = None,
    ):
        self.cur.execute(
            "INSERT INTO '{}' VALUES('{}', '{}', '{}', '{}', '{}', '{}')".format(
                self.COLLECTIONS_TABLE_NAME,
                collection_id,
                owner_id,
                price,
                encrypted_content,
                preview_path,
                status,
            )
        )
        # self.conn.commit()

    '''
    def remove_collection(self, collection_id):
        self.cur.execute(
            "DELETE FROM '{}' WHERE id = '{}'".format(
                self.COLLECTIONS_TABLE_NAME, collection_id
            )
        )
        # self.conn.commit()
    '''

    def update_collection(
            self,
            collection_id: str,
            owner_id: str = None,
            price: float = None,
            encrypted_content: str = None,
            preview_path: str = None,
            status: str = None,
    ):
        """Update any field of the collection table in database."""
        for field_name, field_value in zip(
                [
                    f"{owner_id=}".split("=")[0],
                    f"{price=}".split("=")[0],
                    f"{encrypted_content=}".split("=")[0],
                    f"{preview_path=}".split("=")[0],
                    f"{status=}".split("=")[0],
                ],
                [owner_id, price, encrypted_content, preview_path, status],
        ):  # field_name is the name of the variable
            if field_value:
                # self.cur.execute(
                #     "UPDATE '{}' SET '{}' = '{}' WHERE id = '{}';".format(
                #         self.COLLECTIONS_TABLE_NAME,
                #         field_name,
                #         field_value,
                #         collection_id,
                #     )
                # )
                self.cur.execute(
                    "UPDATE '{}' SET ? = ? WHERE id = ?;".format(
                        self.COLLECTIONS_TABLE_NAME
                    ),
                    field_name,
                    (field_value, collection_id),
                )
                # self.conn.commit()

    def get_all_collections(self):
        self.cur.execute("SELECT * FROM '{}'".format(self.COLLECTIONS_TABLE_NAME))
        return self.cur.fetchall()

    def get_collection_by_id(self, collection_id):
        """
        Find collection from database. Return the collection info if exist, otherwise None.
        @return All data item of the colelction: (id, owner_id, price, encrypted_content, preview_path, status)
        """
        self.cur.execute(
            "SELECT * FROM '{}' WHERE id = '{}'".format(
                self.COLLECTIONS_TABLE_NAME, collection_id
            )
        )
        res = self.cur.fetchall()
        if len(res) > 1:
            raise AssertionError("Fatel error, more than one collecion have same id.")
        return res[0]

    def get_collections_by_user_id(self, user_id):
        """
        Find all collections belongs to user. Return the collection info list.
        @return [(id, owner_id, price, encrypted_content, preview_path, status), ...]
        """
        self.cur.execute(
            "SELECT * FROM '{}' WHERE owner_id = '{}'".format(
                self.COLLECTIONS_TABLE_NAME, user_id
            )
        )
        res = self.cur.fetchall()
        return res

    # manage users TABLE`

    def add_user(
            self,
            user_id: str,
            validation_file: str = None,
            pub_key: str = None,
            balance: float = None,
    ):
        self.cur.execute(
            "INSERT INTO '{}' VALUES('{}', '{}', '{}', '{}')".format(
                self.USER_TABLE_NAME,
                user_id,
                validation_file,
                pub_key,
                balance,
            )
        )
        # self.conn.commit()

    '''
        def remove_user(self, user_id):
        self.cur.execute(
            "DELETE FROM '{}' WHERE id = '{}'".format(self.USER_TABLE_NAME, user_id)
        )
        # self.conn.commit()
    '''

    def update_user(
            self,
            user_id: str,
            validation_file: bytes = None,
            pub_key: str = None,
            balance: float = None,
    ):
        """Update any field of the collection table in database."""
        for field_name, field_value in zip(
                [
                    f"{validation_file=}".split("=")[0],
                    f"{pub_key=}".split("=")[0],
                    f"{balance=}".split("=")[0],
                ],
                [validation_file, pub_key, balance],
        ):
            if field_value:
                self.cur.execute(
                    "UPDATE '{}' SET '{}' = '{}' WHERE id = '{}';".format(
                        self.USER_TABLE_NAME,
                        field_name,
                        field_value,
                        user_id,
                    )
                )
                # self.conn.commit()

    def get_all_users(self):
        self.cur.execute("SELECT * FROM '{}'".format(self.USER_TABLE_NAME))
        return self.cur.fetchall()

    def get_user_by_id(self, user_id) -> typing.List:
        """
        Find user from database. Return the user info if exist, otherwise None.
        @return All data item of the user: (id, validation_file, pub_key, balance)
        """
        self.cur.execute(
            "SELECT * FROM '{}' WHERE id = '{}'".format(self.USER_TABLE_NAME, user_id)
        )
        res = self.cur.fetchall()
        if len(res) > 1:
            raise AssertionError("Fatel error, more than one collecion have same id.")
        return res[0]

    # manage transactions TABLE

    def add_transaction(
            self,
            timestamp: float,
            type: str,
            content: str,
            collection_id: str,
            src_user_id: str,
            dest_user_id: str,
            status: str,
            amount: float,
    ):
        self.cur.execute(
            "INSERT INTO '{}' (TIMESTAMP, TYPE, CONTENT, COLLECTION_ID, SRC_USER_ID, DEST_USER_ID, STATUS, AMOUNT) "
            "VALUES('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(
                self.TRANSACTIONS_TABLE_NAME,
                timestamp,
                type,
                content.replace("'", ""),
                collection_id,
                src_user_id,
                dest_user_id,
                status,
                amount,
            )
        )
        # self.conn.commit()

    def update_transaction(self,
                           timestamp: float,
                           type: str,
                           content: str,
                           collection_id: str,
                           src_user_id: str,
                           dest_user_id: str,
                           status: str,
                           amount: float,
                           ):
        """Update any field of the transaction table in database."""
        for field_name, field_value in zip(
                [
                    f"{type=}".split("=")[0],
                    f"{content=}".split("=")[0],
                    f"{collection_id=}".split("=")[0],
                    f"{src_user_id=}".split("=")[0],
                    f"{dest_user_id=}".split("=")[0],
                    f"{status=}".split("=")[0],
                    f"{amount=}".split("=")[0],
                ],
                [type, content, collection_id, src_user_id, dest_user_id, status, amount],
        ):
            if field_value:
                self.cur.execute(
                    "UPDATE '{}' SET ? = ? WHERE id = ?;".format(
                        self.COLLECTIONS_TABLE_NAME
                    ),
                    field_name,
                    (field_value, timestamp),
                )
                # self.conn.commit()
        pass

    def update_transaction_status(self, timestamp: float, new_status: str):
        self.update_transaction(timestamp, None, None, None, None, None, new_status, None)

    def get_all_transactions(self):
        self.cur.execute("SELECT * FROM '{}'".format(self.TRANSACTIONS_TABLE_NAME))
        return self.cur.fetchall()

    def get_transactions_by_user_id(self, user_id):
        """
        Find all transecitons related to user (either src_user_id or dest_user_id). Return the transeciton info list.
        @return [(id, owner_id, price, encrypted_content, preview_path, status), ...]
        """
        self.cur.execute(
            "SELECT * FROM '{}' WHERE src_user_id = '{}' OR dest_user_id = '{}'".format(
                self.TRANSACTIONS_TABLE_NAME, user_id, user_id
            )
        )
        res = self.cur.fetchall()
        return res

    # general function

    def destroy(self):
        self.cur.close()
        # self.conn.close()
        print("Db connection closed.")


class User:
    """
    If want to User class, must first call User.connect_db() first.
    Note:
        1. Constructors and public methods should check User.db == None first,
            since connect to db first is the **Code of Conduct**.
        2. When use db, always call User.db (cls.db is also acceptable but to
            unify we dont use), and check User.db==None at the begining.
    """

    DEFAULT_BALANCE = 3  # user default balance
    SYSTEM_USER_ID = "System"

    db = None

    def __init__(
            self,
            id: str,
            validation_file: bytes,
            pub_key: str,
            balance: float,
            collections: list,
            transactions: list,
    ):
        """
        id: user name, must be unique, thus can be view as ID
        pub_key: user's RSA public key
        validation_file: json serilized file (contains user_id & AES key) after being encrypted with user's RSA private key
        balance: user's balance of XAV coin
        collections: user's all collections
        transactions: user's all transactions
        """

        if User.db is None:
            raise RuntimeError(
                "Please connect User class to DBmanager by calling User.connect_db() first."
            )

        self.id = id
        self.pub_key = pub_key
        self.validation_file = validation_file
        self.balance = balance
        self.collections = collections
        self.transactions = transactions

    @classmethod
    def fromID(cls, id):
        """
        Load a user by fetching the info from database using user id.
        @AttributeError raise exception if user id doesn't exist.
        """
        if User.db is None:
            raise RuntimeError(
                "Please connect User class to DBmanager by calling connect_db() first."
            )
        if not User.if_id_exist(id):
            raise AttributeError("User doesn't exist with id={}.".format(id))

        _, validation_file, pub_key, balance = User.db.get_user_by_id(id)
        collections = cls._get_collections(id)
        transactions = cls._get_transactions(id)
        return cls(id, validation_file, pub_key, balance, collections, transactions)

    @classmethod
    def new(cls, id):
        """
        Create a new user with a id.
        @AttributeError raise exception if id already exist.
        @return user instance and the RSA private key of user.
        """
        if User.db is None:
            raise RuntimeError(
                "Please connect User class to DBmanager by calling connect_db() first."
            )
        if cls.if_id_exist(id):
            raise AttributeError("User id already exists with id={}.".format(id))

        priv_key, pub_key, aes_key = cls._gen_keys()
        validation_file = cls._gen_validation_file(id, pub_key, aes_key)
        balance = cls.DEFAULT_BALANCE
        user = cls(id, validation_file, pub_key, balance, [], [])
        user._add_to_db()
        return user, priv_key

    @classmethod
    def connect_db(cls, db: DBmanager) -> None:
        """Connect DBmanager to User class. Won't instantiate."""
        if User.db is not None:
            print("Connect failed: User class already has a DBmanager.")
        else:
            User.db = db

    def if_id_exist(user_id):
        """
        Return whether or not the user's id already exists in database.
        @RuntimeError raise exception if haven't conenct a DBmanager isntance to User class.
        TODO: put the detailed logic into a method in DBmanager, and call the method here.
        """
        if User.db == None:
            raise RuntimeError(
                "Please connect User class to DBmanager by calling connect_db() first."
            )
        User.db.cur.execute(
            "SELECT * FROM '{}' WHERE id = '{}'".format(
                User.db.USER_TABLE_NAME, user_id
            )
        )
        return len(User.db.cur.fetchall()) > 0

    @staticmethod
    def _gen_keys() -> typing.Tuple[str, str, str]:
        """
        Generate:
            1. a pair of keys using EEC algorithm (P-256 curve)
            2. a key using AES algorithm (CTR mode, 32-bytes random VI)
        All keys are in bytes form, but is decoded using utf-8 system to strings.
        The AES key (bytes) is also encoded using base64 since the bytes don't follow utf-8 system.
        """

        priv_key_bytes, pub_key_bytes = User._get_rsa_keys()
        priv_key, pub_key = (
            priv_key_bytes.decode("utf-8"),
            pub_key_bytes.decode("utf-8"),
        )

        aes_key_bytes = User._get_aes_key()
        aes_key = base64.b64encode(aes_key_bytes).decode("utf-8")

        return priv_key, pub_key, aes_key

    def _gen_validation_file(id, pub_key: str, aes_key: str) -> str:
        data = json.dumps({"user_id": id, "aes_key": aes_key})  # str
        encrypted_data_bytes = User._rsa_encrypt(
            data.encode("utf-8"), pub_key.encode("utf-8")
        )  # bytes -> bytes
        encrypted_data = base64.b64encode(encrypted_data_bytes).decode(
            "utf-8"
        )  # bytes -> str
        return encrypted_data

    def decrypt_validation_file(self, priv_key: str) -> typing.Tuple[str, str]:
        """
        Decrypt the validation file and return the file content.
        @return `user_id` contained in the validation file and `aes_key` of user's (base64 encoded string)
        """
        encrypted_data_bytes = base64.b64decode(
            self.validation_file.encode("utf-8")
        )  # str -> bytes
        decrypted_data_bytes = User._rsa_decrypt(
            encrypted_data_bytes, priv_key.encode("utf-8")
        )  # bytes -> bytes
        decrypted_data = decrypted_data_bytes.decode("utf-8")  # bytes -> str
        data = json.loads(decrypted_data)

        user_id, aes_key = data["user_id"], data["aes_key"]
        return user_id, aes_key

    def encrypt_temp_collection(self, raw_data: bytes) -> bytes:
        """Encrypt the temporarily decrypted collection's raw data using user's RSA public key."""
        return User._rsa_encrypt(raw_data, self.pub_key.encode("utf-8"))

    @staticmethod
    def decrypt_temp_collection(rsa_encrypted_data: bytes, priv_key: str) -> bytes:
        """Decrypt the temporarily encrypted collection's data using user's RSA private key."""
        return User._rsa_decrypt(rsa_encrypted_data, priv_key.encode("utf-8"))

    def update_db(
            self,
            validation_file: bytes = None,
            pub_key: str = None,
            balance: float = None,
    ):
        User.db.update_user(self.id, validation_file, pub_key, balance)

    def _add_to_db(self):
        """
        - id: user name, must be unique, thus can be view as ID
        - pub_key: user's RSA public key
        - validation_file: json serilized file (2 fields: user_id & AES key) being encrypted using user's RSA private key
        - balance: user's balance of XAV coin
        - transactions: user's all transactions
        """
        if User.db is None:
            raise RuntimeError(
                "Please connect User class to DBmanager by calling User.connect_db() first."
            )
        User.db.add_user(
            self.id,
            self.validation_file,
            self.pub_key,
            round(self.balance, 2),
        )

    @staticmethod
    def _get_collections(id):
        # retrieve user's collections from database
        if User.db is None:
            raise RuntimeError(
                "Please connect User class to DBmanager by calling User.connect_db() first."
            )
        return User.db.get_collections_by_user_id(id)

    @staticmethod
    def _get_transactions(id):
        # retrieve user's transactions from database
        if User.db is None:
            raise RuntimeError(
                "Please connect User class to DBmanager by calling User.connect_db() first."
            )
        tuple_transactions = User.db.get_transactions_by_user_id(id)
        transactions = []
        for tuple_transaction in tuple_transactions:
            transactions.append(Transaction(tuple_transaction[1], tuple_transaction[2], tuple_transaction[3],
                                            tuple_transaction[4], tuple_transaction[5], tuple_transaction[6],
                                            tuple_transaction[7], tuple_transaction[8]))
        return transactions

    @staticmethod
    def _get_rsa_keys() -> typing.Tuple[bytes, bytes]:
        """Get a pair of RSA keys in bytes format. Using the safest 2048 length of random bits to generate keys."""
        random_generator = Random.new().read
        rsa = RSA.generate(2048, random_generator)
        return rsa.exportKey(), rsa.publickey().exportKey()

    @staticmethod
    def _get_aes_key() -> bytes:
        """Get a AES key in bytes format. Using the safest 32-bytes (256-bits) length."""
        return get_random_bytes(32)

    @staticmethod
    def _rsa_encrypt(data: bytes, pub_key: bytes) -> bytes:
        """Encrypt with RSA public key. All operation are in bytes format."""
        pub_key = RSA.import_key(pub_key)
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        encrypted_data_bytes = cipher_rsa.encrypt(data)
        return encrypted_data_bytes

    @staticmethod
    def _rsa_decrypt(data: bytes, priv_key: bytes) -> bytes:
        """
        Decrypt with RSA private key.
        """
        priv_key = RSA.import_key(priv_key)
        cipher_rsa = PKCS1_OAEP.new(priv_key)
        decrypted_data_bytes = cipher_rsa.decrypt(data)  # bytes
        return decrypted_data_bytes

    def is_online(self):
        """Return True if this user is online."""
        return False

    def add_transaction(self, transaction):
        self.transactions.append(transaction)

    def __repr__(self):
        return """
        User:\n\tid={}\n\tpub_key={}\n\tvalidation_file={}\n\tbalance={}\n\tcollections={
        }\n\ttransactions={}
        """.format(
            self.id,
            self.pub_key,
            self.validation_file,
            self.balance,
            self.collections,
            self.transactions,
        )


class Collection:
    """
    If want to Collection class, must first call Collection.connect_db() first.
    Note:
        1. Constructors and public methods should check Collection.db == None first,
            since connect to db first is the **Code of Conduct**.
        2. When use db, always call Collection.db (cls.db is also acceptable but to
            unify we dont use), and check Collection.db==None at the begining.
    """

    _DEFAULT_PRICE = 0.1  # default price of a collection
    _STATUS_CONFIRMED = "confirmed"  # default status
    _STATUS_PENDING = "pending"  # collection on processing, will be confirmed once seller accept and buyer be online
    # after seller accepted
    db = None  # database

    def __init__(
            self,
            id: str,
            owner_id: str,
            price: float,
            encrypted_content: str,
            preview_path: str,
            status: str,
    ):
        """
        @params
        - id: collection unique name
        - owner_id: id of collection's owner
        - price: price of the collection, auto increase by 1 after each transaction
        - encrypted_content: raw data of the collection after encrypted with owner's AES key (in json serialized format)
        - preview_path: low resolution version of the image
        - status: pending if in the middle of a transaction, otherwise confirmed
        """

        if Collection.db is None:
            raise RuntimeError(
                "Please connect Collection class to DBmanager by calling Collection.connect_db() first."
            )

        self.id = id
        self.owner_id = owner_id
        self.price = price
        self.encrypted_content = encrypted_content
        self.preview_path = preview_path
        self.status = status

    @classmethod
    def fromID(cls, id):
        """Load a collection by fetching data from database using colleciton id."""
        if Collection.db is None:
            raise RuntimeError(
                "Please connect Collection class to DBmanager by calling Collection.connect_db() first."
            )
        if not cls.if_id_exist(id):
            raise AttributeError("Collection doesn't exist with id={}.".format(id))
        (
            _,
            owner_id,
            price,
            encrypted_content,
            preview_path,
            status,
        ) = cls.db.get_collection_by_id(id)
        return cls(id, owner_id, price, encrypted_content, preview_path, status)

    @classmethod
    def new(cls, id, owner_id, price, raw_data, aes_key: str):
        """Create a new collection and add to database."""
        if Collection.db is None:
            raise RuntimeError(
                "Please connect Collection class to DBmanager by calling Collection.connect_db() first."
            )
        if cls.if_id_exist(id):
            raise AttributeError("Collection id already exists, please use another id.")
        # price = cls._DEFAULT_PRICE
        aes_bytes = base64.b64decode(aes_key.encode("utf-8"))
        encrypted_content = cls._encrypt_content(raw_data.tobytes(), aes_bytes)
        out_path = os.path.join(Controller.preview_store_path, id)
        cls._gen_save_preview(raw_data, out_path)
        # Image.open(io.BytesIO(preview)).save(out_path)
        status = cls._STATUS_CONFIRMED
        collection = cls(id, owner_id, price, encrypted_content, out_path, status)
        collection._add_to_db()
        return collection

    @classmethod
    def connect_db(cls, db: DBmanager) -> None:
        """Connect DBmanager to Collection class."""
        if Collection.db is not None:
            print("Connect failed: Collection class already has a DBmanager.")
        else:
            cls.db = db

    @staticmethod
    def if_id_exist(collection_id):
        """Return whether the collection's id already exists in database or not."""
        if Collection.db is None:
            raise RuntimeError(
                "Please connect Collection class to DBmanager by calling Collection.connect_db() first."
            )
        Collection.db.cur.execute(
            "SELECT * FROM '{}' WHERE id = '{}'".format(
                Collection.db.COLLECTIONS_TABLE_NAME, collection_id
            )
        )
        return len(Collection.db.cur.fetchall()) > 0

    def _add_to_db(self):
        """
        Add this user to database.
        - id: collection unique name
        - price: price of the collection, auto increase by 1 after each transaction
        - owner_id: id of collection's owner
        - encrypted_content: raw data of the collection after encrypted with owner's AES key
        - preview_path: low resolution version of the image
        - status: pending if in the middle of a transaction, otherwise confirmed
        """
        if Collection.db is None:
            raise RuntimeError(
                "Please connect Collection class to DBmanager by calling Collection.connect_db() first."
            )
        Collection.db.add_collection(
            self.id,
            self.price,
            self.owner_id,
            self.encrypted_content,
            self.preview_path,
            self.status,
        )

    @staticmethod
    def _encrypt_content(data: bytes, aes_key: bytes) -> str:
        """
        Encrypt content using AES (CTR mode, allow arbitrary length of data).
        @param data: raw data of image in bytes
        @return **serialized json string** (e.g., {"nonce": '4Sa\we', "ciphertext": 'wgS2F=D3'})
        """
        cipher = AES.new(aes_key, AES.MODE_CTR)
        ct_bytes = cipher.encrypt(data)
        nonce = base64.b64encode(cipher.nonce).decode("utf-8")
        ct = base64.b64encode(ct_bytes).decode("utf-8")
        result = json.dumps({"nonce": nonce, "ciphertext": ct})
        # print("Encrypt result:", result)
        return result

    def _decrypte_content(data, aes_key: str) -> typing.Union[bytes, None]:
        """
        Decrypt content using AES (CTR mode, allow arbitrary length of data).
        @param data: json serialized string (e.g., {"nonce": '4Sa\we', "ciphertext": 'wgS2F=D3'})
        @return decrypted bytes data if succefully decrypt, otherwise None.
        """
        aes_key_bytes = base64.b64decode(aes_key.encode("utf-8"))
        try:
            b64 = json.loads(data)
            nonce = base64.b64decode(b64["nonce"])
            ct = base64.b64decode(b64["ciphertext"])
            cipher = AES.new(aes_key_bytes, AES.MODE_CTR, nonce=nonce)
            pt = cipher.decrypt(ct)
            # print("Decrypt result:", pt)
            return pt
        except (ValueError, KeyError):
            raise "Incorrect decryption: could due to wrong nonce or AES key."

    def get_raw_data(self, owner: typing.Union[str, User], priv_key: str) -> bytes:
        """
        <high level API> Decrypt the collection and return raw data.
        @param owner [str | User]: collection owner id or an owner's User instance. Pass a User instance will make it
                                   faster, otherwise need to search database using user id to get the user.
        @param priv_key [str]: collection owner's private key.
        @return [bytes]: raw
        data of the collection.
        """
        if isinstance(owner, str):
            owner = Collection.db.get_user_by_id(owner)
        _, aes_key = owner.decrypt_validation_file(priv_key)
        return self._decrypte_content(aes_key)

    @staticmethod
    def _gen_save_preview(raw_data, path):
        """Generate low resolution thumbnail and return its data in bytes."""
        PREVIEW_SIZE = (210, 294)  # default collection thumbnail size (width, height)

        img = raw_data  # Image.open(io.BytesIO(raw_data))
        img.thumbnail((int(img.width * 0.5), int(img.height * 0.5)))
        suffix = path.split('.')[-1]
        if suffix == "png" or suffix == "PNG":
            if not img.mode == "RGBA":
                img = img.convert("RGBA")
        if suffix == "jpg" or suffix == "JPG":
            if not img.mode == "RGB":
                img = img.convert("RGB")
        img.save(path)
        # img_byte_buffer = io.BytesIO()
        # img.save(img_byte_buffer, format=img.format)
        # return img_byte_buffer.getvalue()

    def update_db(
            self,
            owner_id=None,
            price=None,
            encrypted_content=None,
            preview_path=None,
            status=None,
    ):
        self.db.update_collection(
            collection_id=self.id,
            owner_id=owner_id,
            price=price,
            encrypted_content=encrypted_content,
            preview_path=preview_path,
            status=status,
        )

    def update_owner(self, old_owner: User, new_owner: User, priv_key: str):
        """
        Change the collection's owner.

        Procedure:\n
            1. change collection's owner_id
            2. decrypt collection's encrypted_content and get raw data
            3. check whether new owner is online:
                - if online:
                    1. encrypt collection's raw data using new owner's AES key
                - if not online:
                    1. encrypted collection's raw data using new owner's RSA public key
                    2. set the status of the collection as PENDING (when user online again, all collections will be checked. if anyone is in PENDING, AES unlock it and RSA lock it using private key.)
            4. store the new collection's encrypted_content into database
                and update corresponding instances
        """
        # 1. change collection's owner_id
        self.owner_id = new_owner.id
        self.update_db(owner_id=new_owner.id)
        # 2. decrypt collection's encrypted_content and get raw data
        _, aes_key = old_owner.decrypt_validation_file(priv_key)
        raw_data = self._decrypte_content(aes_key)
        # 3. check whether new owner is online
        if new_owner.is_online():
            # 1) encrypt collection's raw data using new owner's AES key
            aes_key = new_owner._get_aes_key()
            encrypted_content = self._encrypt_content(raw_data, aes_key)
        else:
            # 1) encrypted collection's raw data using new owner's RSA public key
            encrypted_content = new_owner.encrypt_temp_collection(raw_data)
            # 2) set the status of the collection as PENDING (when user online again,
            # all collections will be checked. if anyone is in PENDING, AES unlock
            # it and RSA lock it using private key.)
            self.status = Collection._STATUS_PENDING
        # 4. store the new collection's encrypted_content into database
        self.update_db(encrypted_content=encrypted_content)


class Transaction:
    """
    If want to Transaction class, must first call Transaction.connect_db() first.
    Note:
        1. Constructors and public methods should check Transaction.db == None first,
            since connect to db first is the **Code of Conduct**.
        2. When use db, always call Transaction.db (cls.db is also acceptable but to
            unify we don't use), and check Transaction.db==None at the beginning.
    """

    db = None

    TYPE_REQUEST = (
        "request"  # the transaction is a request to a user send by another user
    )
    TYPE_NOTICE = "notice"  # the transaction is a notice to a user lead by the behavior of another user

    STATUS_PENDING = (
        "pending"  # the transaction (request) is waiting to be accepted/rejected
    )
    STATUS_ACCEPTED = (
        "accepted"  # the transaction (request) which was in pending status is accepted
    )
    STATUS_REJECTED = (
        "rejected"  # the transaction (request) which was in pending status is rejected
    )
    STATUS_CLOSED = (
        "closed"   # the transaction (request) which was in accepted/rejected status is closed
    )

    STATUS_UNSEEN = (
        "unseen"  # the transaction (notice) is sent but unseen by the receiver
    )
    STATUS_SEEN = "seen"  # the transaction (notice) is sent and seen by the receiver

    def __init__(
            self,
            timestamp,
            type,
            content,
            collection_id,
            src_user_id,
            dest_user_id,
            status,
            amount,
    ):
        """Internal use only! Please use Transaction.new()."""
        if Transaction.db is None:
            raise RuntimeError(
                "Please connect Transaction class to DBmanager by calling Transaction.connect_db() first."
            )

        self.timestamp = timestamp
        self.type = type
        self.content = content.replace("'", "")
        self.collection_id = collection_id
        self.src_user_id = src_user_id
        self.dest_user_id = dest_user_id
        self.status = status
        self.amount = amount

    @classmethod
    def new(
            cls,
            type,
            content,
            collection_id,
            src_user_id,
            dest_user_id,
            status,
            amount: float = None,
    ):
        """Create a new transaction."""
        new_transaction = cls(
            time.time(),
            type,
            content.replace("'", ""),
            collection_id,
            src_user_id,
            dest_user_id,
            status,
            amount,
        )
        new_transaction._add_to_db()
        return new_transaction

    @classmethod
    def connect_db(cls, db: DBmanager):
        if Transaction.db is not None:
            print("Connect failed: Transaction class already has a DBmanager.")
        else:
            Transaction.db = db

    def _add_to_db(self):
        """
        - id: collection unique name
        - price: price of the collection, auto increase by 1 after each transaction
        - owner_id: id of collection's owner
        - encrypted_content: raw data of the collection after encrypted with owner's AES key
        - preview_path: low resolution version of the image
        - status: pending if in the middle of a transaction, otherwise confirmed
        """
        if Transaction.db is None:
            raise RuntimeError(
                "Please connect Transaction class to DBmanager by calling Transaction.connect_db() first."
            )
        Transaction.db.add_transaction(
            self.timestamp,
            self.type,
            self.content,
            self.collection_id,
            self.src_user_id,
            self.dest_user_id,
            self.status,
            self.amount,
        )

    def _update_status(self, new_status: str):
        self.db.update_transaction_status(self.timestamp, new_status)

    def __repr__(self):
        return "[{}] {}->{}: {} | {} | {} | {}".format(
            self.timestamp or "None",
            self.src_user_id or "None",
            self.dest_user_id or "None",
            self.content.replace("'", "") or "None",
            self.status or "None",
            self.amount or "None",
            self.type or "None",
        )


class Controller:
    db = None
    preview_store_path = None

    def __init__(self, preview_store_path: str):
        Controller.db = DBmanager()
        # maintain these lists to improve the searching speed
        self._init_models()

        self._user_list = self._init_user_list()
        self._collection_list = self._init_collection_list()
        self._transaction_list = self._init_transaction_list()

        Controller.preview_store_path = preview_store_path
        # self.store_all_preview_to_local()

        # do rest initialization
        pass

    # def store_all_preview_to_local(self):
    # for collection in self._collection_list:
    # raw_data = collection.preview_path
    # if isinstance(raw_data, str):
    # raw_data = raw_data.encode()
    # img = Image.open(io.BytesIO(raw_data))
    # out_path = os.path.join(self.preview_store_path, collection.id)
    # img.save(out_path)

    def sign_up(self, user_id: str) -> str:
        """
        Sign up a user, user only need to provide a unique username as id.
        Return user's private key if success, otherwise None.
        (Note: user_id cannot include whitespace.)
        """
        # check whether user_id include whitespace & whether user_id is unique
        if user_id.find(" ") != -1 or User.if_id_exist(user_id):
            return None

        # create a new user, update in database and update Controller's list
        user, priv_key = User.new(user_id)  # database updated here
        self._add_user(user)

        return priv_key[32:-30]

    def sign_in(self, user_id: str, priv_key: str):
        """
        Sign in using user_id and user's private key. Return True if success.
        (Note: private key will only be stored in local variable to prevent safety issue.)
        Pre-request: User class has already been instanciated at least once.
        """
        # check whether user_id exist in database
        if not User.if_id_exist(user_id):  # ignore the db if pre-request if fulfilled
            return False

        # using priv_key decrypt user's validation file, then json.loads the string
        # content to get a json structure, if the user_id file in json structure can
        # match the user_id provided by user, then success, and return True. otherwise,
        # return false (TBD: along with failure reason)
        user = self._find_user(user_id)
        try:
            decrypted_id, _ = user.decrypt_validation_file(priv_key)
        except Exception as e:
            traceback.print_exc()
            return False

        if user_id != decrypted_id:
            return False

        # check if there is any transaction of this user that is a reply notice
        # from a buying request. if so, the related collection's status should
        # be ACCEPTED, and set the status to CONFIRMED.
        for transaction in user.transactions:
            if transaction.src_user_id == user_id and transaction.status == Transaction.STATUS_ACCEPTED:
                collection = self._find_collection(transaction.collection_id)
                raw_data = user.decrypt_temp_collection(collection.encrypted_content.encode("utf-8"), priv_key)
                encrypted_content = Collection._encrypt_content(raw_data, user._get_aes_key())
                collection.update_db(encrypted_content=encrypted_content)
                transaction._update_status(Transaction.STATUS_CLOSED)

        return True

    def upload(
            self, collection_id: str, creator_id: str, price: float, raw_data, priv_key: str
    ):
        """
        Upload a collection to database. Return True if success.
        (Note: private key and collection's raw data will only be stored in local variable to prevent safety issue.)
        (Note: need to update display since database is updated.)
        """
        # check whether collection id (which is also the user-chose title for the collection) is unique in database
        # if Collection.if_id_exist(collection_id):
        #    return False

        # create a new collection and add to collection_list
        creator = self._find_user(creator_id)
        _, aes_key = creator.decrypt_validation_file(priv_key)
        new_collection = Collection.new(collection_id, creator_id, price, raw_data, aes_key)
        creator.collections.append(new_collection)
        self._add_collection(new_collection)

        # create a notice and add to user and Controller
        upload_notice = Transaction.new(
            Transaction.TYPE_NOTICE,
            "successfully upload collection {}.".format(collection_id),
            collection_id,
            User.SYSTEM_USER_ID,
            creator_id,
            Transaction.STATUS_UNSEEN,
            price,
        )
        creator.add_transaction(upload_notice)
        self._add_transaction(upload_notice)

        return True

    def buy(self, buyer_id: str, collection_id: str):
        """
        User (id=buyer_id) send a buy request to the collection's owner.
        Return Fales if buyer dont have enough money.
        (Note: buyer's money will be reduced only when owner accept the buying request)
        """
        return self.__abandond_buy(buyer_id, collection_id)
        # self._accept_a_request(buy_request, collection, buyer, owner, priv_key)

    def __abandond_buy(self, buyer_id: str, collection_id: str):
        """
        User (id=buyer_id) send a buy request to the collection's owner.
        Return Fales if buyer dont have enough money.
        (Note: buyer's money will be reduced only when owner accept the buying request)
        """
        # buyer need to have enough money, the money will be reduced first
        buyer = self._find_user(buyer_id)
        collection = self._find_collection(collection_id)
        if buyer.balance < collection.price:
            return False

        owner_id = collection.owner_id
        # reduce money from buyer account
        buyer.balance -= collection.price
        # create notice
        prebuy_notice = Transaction.new(
            Transaction.TYPE_NOTICE,
            "Pay and send buying request to {} successfully".format(owner_id),
            collection_id,
            User.SYSTEM_USER_ID,
            buyer_id,
            Transaction.STATUS_UNSEEN,
            None,
        )
        # send notice to user and Controller
        buyer.add_transaction(prebuy_notice)
        self._add_transaction(prebuy_notice)

        # create buying request
        buy_request = Transaction.new(
            Transaction.TYPE_REQUEST,
            "{} to {}: requested to buy {}.".format(buyer_id, owner_id, collection_id),
            collection_id,
            buyer_id,
            owner_id,
            Transaction.STATUS_PENDING,
            collection.price,
        )
        # add request to user and Controller
        owner = self._find_user(owner_id)
        owner.add_transaction(buy_request)
        self._add_transaction(buy_request)
        return True

    def __abandond_response(
            self, user_id: str, transaction: Transaction, accept: bool, priv_key: str = None
    ):
        """
        User with `user_id` reply a transaction of the user's. If accept is True, then priv_key must be provided.
        Currently only support reply to a buying request.
        """
        if transaction.type != Transaction.TYPE_REQUEST:
            raise RuntimeError(
                'Can only reply to a transaction of type "request" (current type: {}).'.format(
                    transaction.type
                )
            )
        if transaction.status != Transaction.STATUS_PENDING:
            raise RuntimeError(
                "Cannot reply a request that has already been accepted/rejected."
            )
        if transaction.dest_user_id != user_id:
            raise RuntimeError(
                "Transaction doesn't belong to this user (user_id: {}, dest_user_id: {})".format(
                    user_id, transaction.dest_user_id
                )
            )

        # prepare variables
        buyer_id = transaction.src_user_id
        seller_id = user_id
        collection_id = transaction.collection_id
        buyer = self._find_user(buyer_id)
        seller = self._find_user(seller_id)
        collection = self._find_collection(collection_id)

        if accept:  # accept the buying request
            if priv_key == None:
                raise AttributeError(
                    "User's private key must be provided if accept the buying request."
                )
            self._accept_a_request(transaction, collection, buyer, seller, priv_key)

        else:  # reject the buying request
            self._reject_a_request(transaction, collection, buyer, seller)
            return False

    def response(
            self, user_id: str, transaction: Transaction, accept: bool, priv_key: str = None
    ):
        return True

    def getBalanceByID(self, user_id: str):
        """Get the balance of the user"""
        user = self._find_user(user_id)
        return user.balance

    def recharge(self, user_id: str, amount: float):
        """Recharge XAV coins to user's account. Return True if success."""
        # add amount of XAV to user's account (User instance)
        if amount <= 0:
            raise ValueError("Recharge amount must be a positive number.")
            # print("Recharge amount must be a positive number.")
            # return False
        user = self._find_user(user_id)
        user.balance += amount
        user.update_db(balance=user.balance + amount)
        return True

    def download(self, collection_id: str, priv_key: str):
        """
        User downlaod the original data of one of user's collection. Return
        the collection's raw data if successful, otherwise None.
        """
        # find the collection owner's validation_file and encrypted_content
        collection = self._find_collection(collection_id)
        owner = self._find_user(collection.owner_id)
        _, aes_key = owner.decrypt_validation_file(priv_key)
        raw_data = collection.get_raw_data(owner, priv_key)

        # return the raw_data if success, otherwise None
        return raw_data

    @staticmethod
    def _init_models() -> None:
        """Init DBmanager, User, Collection, Transaction by connect db to them."""
        User.connect_db(Controller.db)
        Collection.connect_db(Controller.db)
        Transaction.connect_db(Controller.db)
        print("Connect DBmanager to User, Collection and Transaction.")

    def _init_user_list(self) -> typing.List[User]:
        """
        Initialized Controller._user_list by finding and fetching all user info from
        database, and load to User instances. Return a list of all Users.
        """
        all_user_list = []
        all_user_info = self.db.get_all_users()
        for one_user_info in all_user_info:
            user = User.fromID(one_user_info[0])
            all_user_list.append(user)
        return all_user_list

    def _init_collection_list(self) -> typing.List[Collection]:
        """
        Initialized Controller._collection_list by finding and fetching all collection info from
        database, and load to Collection instances. Return a list of all Collections.
        """
        all_collection_list = []
        all_collection_info = self.db.get_all_collections()
        for one_collection_info in all_collection_info:
            collection = Collection.fromID(one_collection_info[0])
            all_collection_list.append(collection)
        return all_collection_list

    def _init_transaction_list(self) -> typing.List[Transaction]:
        """
        Initialized Controller._transaction_list by finding and fetching all transaction info from
        database, and load to Transaction instances. Return a list of all Transactions.
        """
        all_transaction_list = []
        all_transaction_info = self.db.get_all_transactions()
        for one_transaction_info in all_transaction_info:
            # self,timestamp,type,content,collection_id,src_user_id,dest_user_id,status,amount,
            (
                _,
                timestamp,
                type,
                content,
                collection_id,
                src_user_id,
                dest_user_id,
                status,
                amount,
            ) = one_transaction_info
            transaction = Transaction(
                timestamp,
                type,
                content.replace("'", ""),
                collection_id,
                src_user_id,
                dest_user_id,
                status,
                amount,
            )
            all_transaction_list.append(transaction)
        return all_transaction_list

    def _find_user(self, user_id: str) -> [User, None]:
        """
        Find user's instance from _user_list. Return the user's instance
        if successful, otherwise None.
        """
        # search for the user with user_id within _user_list and return it
        for user in self._user_list:
            if user.id == user_id:
                return user
        # return None if cannot find the user.
        return None

    def _find_collection(self, collection_id: str) -> [Collection, None]:
        """
        Find collection's instance from _collection_list. Return the collection's
        instance if successful, otherwise None.
        """
        # search for the collection with collection_id within _collection_list and return it
        for collection in self._collection_list:
            if collection.id == collection_id:
                return collection

        # return None if cannot find the collection
        return None

    def _find_transaction(
            self,
            time_range: typing.Union[typing.Tuple[float, float], None] = None,
            type: typing.Union[str, None] = None,
            collection_id: typing.Union[str, None] = None,
            src_user_id: typing.Union[str, None] = None,
            dest_user_id: typing.Union[str, None] = None,
            status: typing.Union[str, None] = None,
            amount_range: typing.Union[typing.Tuple[float, float], None] = None,
    ) -> typing.List[Transaction]:
        """
        Find all the transactions that fulfill the searching requirement. Return
        all qualified transecitons in a list. List is empty if no transaction is found.
        If no requirement is given, return all transactions. Return empty list if no
        transaction match the requirements.
        @param time_range [List[float, float]]: transactions whose timestamp fulfill: time_range[0] <= timestamp <= time_ramge[1]
        @param type | collection_id | src_user_id | dest_user_id | status | amount_range: transaction who has same value
        @param amount_range [List[float, float]]: transactions whose amount fulfill: amount_range[0] <= amount <= amount_range[1]
        """
        # search for the transactions with the right field value (start from the field has minimum search space)
        res_transaction_list = copy.deepcopy(self._transaction_list)
        if src_user_id is not None:
            for transaction in res_transaction_list:
                if transaction.src_user_id != src_user_id:
                    res_transaction_list.remove(transaction)
        if dest_user_id is not None:
            for transaction in res_transaction_list:
                if transaction.dest_user_id != dest_user_id:
                    res_transaction_list.remove(transaction)
        if collection_id is not None:
            for transaction in res_transaction_list:
                if transaction.collection_id != collection_id:
                    res_transaction_list.remove(transaction)
        if status is not None:
            for transaction in res_transaction_list:
                if transaction.status != status:
                    res_transaction_list.remove(transaction)
        if amount_range is not None:
            for transaction in res_transaction_list:
                if (
                        transaction.amount < amount_range[0]
                        or transaction.amount > amount_range[1]
                ):
                    res_transaction_list.remove(transaction)
        if time_range is not None:
            for transaction in res_transaction_list:
                if (
                        transaction.timestamp < time_range[0]
                        or transaction.timestamp > time_range[1]
                ):
                    res_transaction_list.remove(transaction)
        if type is not None:
            for transaction in res_transaction_list:
                if transaction.type != type:
                    res_transaction_list.remove(transaction)

        return res_transaction_list

    def _add_transaction(self, transaction: Transaction):
        """
        Add a transaction to Controller's transaction list.
        No need to update database, model.new has done that.
        """
        self._transaction_list.append(transaction)

    def _add_collection(self, collection: Collection):
        """
        Add a collection to Controller's collection list.
        No need to update database, model.new has done that.
        """
        self._collection_list.append(collection)

    def _add_user(self, user: User):
        """
        Add a user to Controller's user list.
        No need to update database, model.new has done that.
        """
        self._user_list.append(user)

    @staticmethod
    def _get_collection_raw_data(
            collection: Collection, owner: User, priv_key: str
    ) -> bytes:
        """Decrypt the collection and return raw data."""
        _, aes_key = owner.decrypt_validation_file(priv_key)
        return collection._decrypte_content(aes_key)

    def _reject_a_request(
            self, request: Transaction, collection: Collection, buyer: User, seller: User
    ):
        """
        Reject a buying request.

        Update request status as REJECTED, and return money to buyer, then create and
        send an UNSEEN notice for both buyer and seller to notify the reject behavior.
        """
        request.status = Transaction.STATUS_REJECTED  # update request status
        buyer.balance += collection.price  # return money to buyer
        # create a transaction to notice the buyer
        self._send_result_notice_of_buy_request(
            collection.id,
            buyer,
            seller,
            "buying request for {} is rejected".format(collection.id),
            "you have rejected {}'s request of buying {}".format(
                buyer.id, collection.id
            ),
        )

    def _accept_a_request(
            self,
            transaction: Transaction,
            collection: Collection,
            buyer: User,
            seller: User,
            priv_key: str,
    ):
        """
        Accept a buying request.
        Update the owner of the collection and send a notice to both buyer and seller.
        """
        # update request status
        transaction.status = Transaction.STATUS_ACCEPTED
        # reject all other buy requests
        other_buy_requests = self._find_transaction(
            type=Transaction.TYPE_REQUEST,
            collection_id=collection.id,
            dest_user_id=seller.id,
        )  # Assumption: all request with collection id is a buying request.
        for req in other_buy_requests:
            self._reject_a_request(req, collection, buyer, seller)
        # update collection's owner
        collection.update_owner(seller, buyer, priv_key)
        # send notification to both buyer and owner
        self._send_result_notice_of_buy_request(
            collection.id,
            buyer,
            seller,
            "accepted {}'s buying request for {}".format(buyer.id, collection.id),
            "buying request for {} is accepted".format(collection.id),
        )

    def _send_result_notice_of_buy_request(
            self,
            collection_id: str,
            buyer: User,
            seller: User,
            content_to_buyer: str,
            content_to_seller: str,
    ):
        """
        Create and send notice for both buyer and seller, notify the buy request's accepted/rejected.
        The difference of two difference reply shows in the `content_to_buyer` and `content_to_seller`.
        """
        # create a transaction to notice the buyer
        notice_to_buyer = Transaction.new(
            Transaction.TYPE_NOTICE,
            content_to_buyer,
            collection_id,
            seller.id,
            buyer.id,
            Transaction.STATUS_UNSEEN,
            None,
        )
        buyer.add_transaction(notice_to_buyer)
        self._add_transaction(notice_to_buyer)

        # create a transaction to notice rejector
        notice_to_seller = Transaction.new(
            Transaction.TYPE_NOTICE,
            content_to_seller,
            collection_id,
            User.SYSTEM_USER_ID,
            buyer.id,
            Transaction.STATUS_UNSEEN,
            None,
        )
        seller.add_transaction(notice_to_seller)
        self._add_transaction(notice_to_seller)

    @staticmethod
    def deinit():
        Controller.db.cur.close()
        Controller.db.conn.close()

    def overview(self):
        """Print overview of the users, collections and transactions."""
        print(
            "Database overview:\n\t\
            {} user record: {},\n\t\
            {} collections: {},\n\t\
            {} transactions.".format(
                len(self._user_list),
                [user.id for user in self._user_list],
                len(self._collection_list),
                [collection.id for collection in self._collection_list],
                len(self._transaction_list),
            )
        )


backend_requests = dict()
backend_results = dict()


class Main:
    ctrl = None

    def __init__(self, ctrl: Controller):
        Main.ctrl = ctrl

    @staticmethod
    def start():
        """Start event loop."""
        while 1:
            if len(backend_requests) != 0:
                # get one request
                for req_name_id in backend_requests.keys():
                    params = backend_requests.pop(req_name_id)
                    break
                req_name = req_name_id.split("-")[0]
                print(req_name, params)
                if req_name == "signin":
                    ret = Main.ctrl.sign_in(params[0], params[1])
                elif req_name == "signup":
                    ret = Main.ctrl.sign_up(params[0])
                elif req_name == "upload":
                    ret = Main.ctrl.upload(params[0], params[1], params[2], params[3])
                elif req_name == "buy":
                    ret = Main.ctrl.buy(params[0], params[1])
                elif req_name == "response":
                    ret = Main.ctrl.response(params[0], params[1], params[2], params[3])
                elif req_name == "recharge":
                    ret = Main.ctrl.recharge(params[0], params[1])
                elif req_name == "download":
                    ret = Main.ctrl.download(params[0], params[1])
                else:
                    raise ValueError(
                        "Illegal function name, can only be within (signin, signup, upload, buy, response, recharge, "
                        "download) "
                    )
                backend_results[req_name_id] = ret
