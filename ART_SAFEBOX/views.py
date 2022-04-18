from django.shortcuts import render, Http404
from django.http import JsonResponse, StreamingHttpResponse
from . import accounts
from . import models


def signup(request):
    return render(request, 'signup.html')


def signupAction(request):
    if request.method != "POST":
        return JsonResponse({}, status=404)
    user_id = request.POST.get('id')
    status, pwd = models.new_id_validation(user_id)
    return JsonResponse({"status": status, "msg": pwd}, status=200)


def signin(request):
    return render(request, 'signin.html')


def signinAction(request):
    if request.method != "POST":
        return JsonResponse({}, status=404)
    user_id = request.POST.get('id')
    pwd = models.reformat_key(request.POST.get('pwd'))
    status = models.account_validation(user_id, pwd)
    res = JsonResponse({"status": status}, status=200)
    if status == 1:
        account = accounts.Account(user_id)
        res.set_cookie("uid", user_id)
        res.set_cookie("info", account.set_cookie_content(user_id, pwd))
        accounts.AccountManager.add_online_account(account)
    return res


def checkSigninState(request):
    if request.method != "POST":
        return JsonResponse({}, status=404)
    user_id = request.COOKIES.get("uid")
    cookie_content = request.COOKIES.get("info")
    cookie_content = accounts.AccountManager.check_login(user_id, cookie_content)
    if cookie_content is None:
        msg = "Your signin has expired, please sign in again."
        res = JsonResponse({"status": 0, "msg": msg}, status=200)
        res.delete_cookie("uid")
        res.delete_cookie("info")
        return res
    res = JsonResponse({"status": 1}, status=200)
    res.set_cookie("info", cookie_content)
    return res


def signOutAction(request):
    if request.method != "POST":
        return JsonResponse({}, status=404)
    res = JsonResponse({"status": 1}, status=200)
    accounts.AccountManager.remove_online_account_by_id(request.COOKIES.get("uid"))
    res.delete_cookie("uid")
    res.delete_cookie("info")
    return res


def upload(request):
    if request.method != "POST":
        return JsonResponse({}, status=404)
    img = request.FILES['source']
    title = request.POST.get('title')
    price = request.POST.get('price')
    user_id = request.COOKIES.get("uid")
    cookie_content = request.COOKIES.get("info")
    cookie_content = accounts.AccountManager.check_login(user_id, cookie_content)
    if cookie_content is None:
        res = JsonResponse({"status": 0, 'msg': "Your signin is expired, please sign in again."}, status=200)
        res.delete_cookie("uid")
        res.delete_cookie("info")
        return res
    re, msg = models.upload_img(img, title, price, user_id, accounts.AccountManager.get_priv_key(user_id, cookie_content))
    if not re:
        res = JsonResponse(
            {"status": 0, 'msg': msg}, status=200)
        res.set_cookie("info", cookie_content)
        return res
    res = JsonResponse({"status": 1}, status=200)
    res.set_cookie("info", cookie_content)
    return res


def purchase(request):
    if request.method != "POST":
        return JsonResponse({}, status=404)
    title = request.POST.get('title')
    user_id = request.COOKIES.get("uid")
    cookie_content = request.COOKIES.get("info")
    cookie_content = accounts.AccountManager.check_login(user_id, cookie_content)
    if cookie_content is None:
        res = JsonResponse({"status": 0}, status=200)
        res.delete_cookie("uid")
        res.delete_cookie("info")
        return res
    status = models.do_purchase(user_id, title)
    res = JsonResponse({"status": status}, status=200)
    res.set_cookie("info", cookie_content)
    return res


def respond(request):
    pass


def recharge(request):
    if request.method != "POST":
        return JsonResponse({}, status=404)
    amount = request.POST.get('amount')
    user_id = request.COOKIES.get("uid")
    cookie_content = request.COOKIES.get("info")
    cookie_content = accounts.AccountManager.check_login(user_id, cookie_content)
    if cookie_content is None:
        res = JsonResponse({"status": 0}, status=200)
        res.delete_cookie("uid")
        res.delete_cookie("info")
        return res
    status = models.recharge_by_id(user_id, amount)
    res = JsonResponse({"status": status}, status=200)
    res.set_cookie("info", cookie_content)
    return res


def download(request):
    if request.method != "GET":
        return Http404(request)
    user_id = request.COOKIES.get("uid")
    cookie_content = request.COOKIES.get("info")
    cookie_content = accounts.AccountManager.check_login(user_id, cookie_content)
    if cookie_content is None:
        return Http404(request)
    title = request.GET.get('title')
    generator = models.download_img(title)
    if generator is None:
        return Http404(request)
    response = StreamingHttpResponse(generator)
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="{0}"'.format(title)
    return response


def personal(request):
    user_id = request.COOKIES.get("uid")
    balance = models.get_balance_by_id(user_id)
    return render(request, "personal.html", context={'user_id': user_id,
                                                     'balance': balance,
                                                     'collections': models.get_previews_by_id(user_id)})


def index(request):
    return render(request, 'index.html', context={'collections': models.get_all_previews()})


def home(request):
    user_id = request.COOKIES.get("uid")
    balance = models.get_balance_by_id(user_id)
    return render(request, 'home.html', context={'user_id': user_id,
                                                 'balance': balance,
                                                 'collections': models.get_others_previews(user_id)})


def other(request):
    if request.method != "GET":
        return Http404(request)
    other_id = request.GET.get('id')
    if not models.new_id_validation(other_id):
        return Http404(request)
    user_id = request.COOKIES.get("uid")
    cookie_content = request.COOKIES.get("info")
    cookie_content = accounts.AccountManager.check_login(user_id, cookie_content)
    if cookie_content is None:
        return render(request, 'others_unsigned.html', context={
            'other_id': other_id,
            'collections': models.get_previews_by_id(other_id)})
    balance = models.get_balance_by_id(user_id)
    return render(request, 'others.html', context={
        'other_id': other_id,
        'user_id': user_id,
        'balance': balance,
        'collections': models.get_previews_by_id(other_id)})
