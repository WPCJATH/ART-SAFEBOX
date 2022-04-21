import io
import threading
import traceback
import random

from django.core.files.uploadedfile import TemporaryUploadedFile, InMemoryUploadedFile
from PIL import Image

from .backend import Controller
random.seed(39)

ctrl = Controller("static/previews/")

key_begin = "-----BEGIN RSA PRIVATE KEY-----\n"
key_end = "\n-----END RSA PRIVATE KEY-----"


class Collection:
    def __init__(self, idx, title, owner, path, price):
        self.title = title
        self.owner = owner
        self.path = path
        self.price = price
        self.idx = idx


class Transaction:
    def __init__(self, id, collection_id, content, src, amount, status):
        self.id = id
        self.content = content
        self.collection_id = collection_id
        self.src = src
        self.amount = []
        if amount is not None and amount != "None":
            self.amount.append(amount)
        self.pending = []
        if status == "pending":
            self.pending.append(1)


def get_all_transactions(user_id):
    transactions = []
    for idx, transaction in enumerate(ctrl.get_transactions_by_user_id(user_id)):
        transactions.append(
            Transaction(transaction.id, transaction.collection_id, transaction.content, transaction.src_user_id
                        , transaction.amount, transaction.status))
    transactions.reverse()
    return transactions


def get_all_previews(shuffle=True):
    collections = []
    for idx, collection in enumerate(ctrl.collection_list):
        try:
            if collection.status != "pending":
                collections.append(
                    Collection(idx, collection.id, collection.owner_id, collection.id, collection.price))
        except:
            traceback.print_exc()
            pass
    if shuffle:
        random.shuffle(collections)
    return collections


def get_previews_by_id(user_id):
    collections_ = []
    collections = get_all_previews(False)
    for collection in collections:
        if collection.owner == user_id:
            collections_.append(collection)
    return collections_


def get_others_previews(user_id):
    collections_ = []
    collections = get_all_previews(False)
    for collection in collections:
        if collection.owner != user_id:
            collections_.append(collection)
    return collections_


def do_purchase(user_id, title):
    try:
        re = ctrl.buy(user_id, title)
        if re:
            return 1, "Your request is successfully sent to the user, please wait for the owner process it. You will " \
                      "be refined if the owner rejects your request. "
    except:
        traceback.print_exc()
    return 0, "You balance is not enough for buying the artwork."


def respond(user_id, src_id, transaction_id, collection_id, isAccept, priv_key=None):
    try:
        ctrl.response(user_id, src_id, transaction_id, collection_id, isAccept, priv_key)
        return True
    except:
        traceback.print_exc()
        return False


def reformat_key(key):
    return key_begin + key.replace(' ', '') + key_end


def account_validation(user_id, pwd):
    re = ctrl.sign_in(user_id, pwd)
    if re:
        return 1
    return 0


def new_id_validation(user_id):
    pwd = ctrl.sign_up(user_id)
    if not pwd:
        return 0, ""
    else:
        return 1, pwd


def recharge_by_id(user_id, amount):
    try:
        re = ctrl.recharge(user_id, float(amount))
        if re:
            return 1
        return 0
    except:
        traceback.print_exc()
        return 0


def get_balance_by_id(user_id):
    try:
        return "{:.2f}".format(ctrl.getBalanceByID(user_id))
    except:
        traceback.print_exc()
        return None


def upload_img(source, title, price, user_id, priv_key):
    if priv_key is None or title is None or source is None:
        return False, "Invalid file."
    suffix = source.name.split('.')[-1]
    if suffix not in ["JPG", "jpg", "PNG", "png"]:
        return False, "Unsupported file type. *.jpg or *.png only."
    try:
        # Image.verify() will destroy the object, so we have to prepare 2 pieces of the Image object
        image = None
        image_to_verify = None
        if isinstance(source, TemporaryUploadedFile):
            image_to_verify = Image.open(source.temporary_file_path())
            image = Image.open(source.temporary_file_path())
        elif isinstance(source, InMemoryUploadedFile):
            image_to_verify = Image.open(source.file)
            image = Image.open(source.file)
        image_to_verify.verify()
    except:
        traceback.print_exc()
        return False, "Invalid file."
    try:
        re = ctrl.upload(title + '.' + suffix, user_id, float(price), image, priv_key)
        return re, ""
    except:
        traceback.print_exc()
        return False, "The title has been taken by other collections, please reset the title"


def download_img(title, priv_key):
    try:
        return io.BytesIO(ctrl.download(title, priv_key))
    except:
        traceback.print_exc()
        return None


def online_check(user, priv_key):
    try:
        ctrl.online_check(user, priv_key)
    except:
        traceback.print_exc()
