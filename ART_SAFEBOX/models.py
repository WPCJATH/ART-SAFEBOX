import io
import traceback
import random

from django.core.files.uploadedfile import TemporaryUploadedFile, InMemoryUploadedFile
from PIL import Image

from .backend import Controller

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


'''
ctrl.sign_in(params[0], params[1])
ctrl.sign_up(params[0])
ctrl.upload(params[0], params[1], params[2], params[3])
ctrl.buy(params[0], params[1])
ctrl.response(params[0], params[1], params[2], params[3])
ctrl.recharge(params[0], params[1])
ctrl.download(params[0], params[1])
ctrl._collection_list
'''


def get_all_previews():
    collections = []
    for idx, collection in enumerate(ctrl._collection_list):
        try:
            collections.append(
                Collection(idx, collection.id, collection.owner_id, collection.id, collection.price))
        except:
            pass
    random.shuffle(collections)
    return collections


def get_previews_by_id(user_id):
    collections_ = []
    collections = get_all_previews()
    for collection in collections:
        if collection.owner == user_id:
            collections_.append(collection)
    return collections_


def get_others_previews(user_id):
    collections_ = []
    collections = get_all_previews()
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
        return False, "Invalid file. 0"
    suffix = source.name.split('.')[-1]
    print(suffix)
    if suffix not in ["JPG", "jpg", "PNG", "png"]:
        return False, "Unsupported file format. *.jpg or *.png only."
    try:
        image = None
        b_content = None
        if isinstance(source, TemporaryUploadedFile):
            image = Image.open(source.temporary_file_path())
            b_content = open(source.temporary_file_path(), 'rb').read()
        elif isinstance(source, InMemoryUploadedFile):
            image = Image.open(source.file)
            b_content = source.file.read()
        # image.verify()
    except:
        traceback.print_exc()
        return False, "Invalid file. 1"
    try:
        print(type(b_content))
        re = ctrl.upload(title + '.' + suffix, user_id, float(price), image,
                         priv_key)
        return re, ""
    except:
        traceback.print_exc()
        return False, "The title has been taken by other collections, please reset the title"


def download_img(title, chunk_size=512):
    try:
        with open('static/previews/' + title, 'rb') as f:
            while True:
                c = f.read(chunk_size)
                if c:
                    yield c
                else:
                    break
    except:
        return None
