# Near-misses without a qualifying import go above the framework
# imports: the import must precede the call for a bare sink to count.
# Qualified `flask.redirect` / `flask.url_for` need no import.


def _no_import():
    # ok: python-pii-in-url
    return redirect(user.email)


def _no_import_url_for():
    # ok: python-pii-in-url
    return url_for("profile", email=user.email)


def _no_import_django():
    # ok: python-pii-in-url
    return HttpResponseRedirect(user.email)


def _no_import_permanent():
    # ok: python-pii-in-url
    return HttpResponsePermanentRedirect(user.email)


def _no_import_starlette():
    # ok: python-pii-in-url
    return RedirectResponse(user.email)


def redirect(url):
    return url


def url_for(endpoint, **values):
    return endpoint


def _home_grown_redirect():
    # ok: python-pii-in-url
    return redirect(user.email)


def _home_grown_url_for():
    # ok: python-pii-in-url
    return url_for("profile", email=user.email)


from helpers import url_for  # noqa: E402,F811
from myapp.http import HttpResponseRedirect  # noqa: E402,F811
from myapp.responses import RedirectResponse  # noqa: E402,F811
from mylib import redirect  # noqa: E402,F811


def _wrong_import_redirect():
    # ok: python-pii-in-url
    return redirect(user.email)


def _wrong_import_url_for():
    # ok: python-pii-in-url
    return url_for("profile", email=user.email)


def _wrong_import_django():
    # ok: python-pii-in-url
    return HttpResponseRedirect(user.email)


def _wrong_import_starlette():
    # ok: python-pii-in-url
    return RedirectResponse(user.email)


# Mid-file imports are the bare-sink gates under test: the near-misses
# above them stay silent.
from django.http import (  # noqa: E402,F811
    HttpResponsePermanentRedirect,
    HttpResponseRedirect,
)
from django.shortcuts import redirect  # noqa: E402,F811
from flask import (  # noqa: E402,F811
    redirect,
    url_for,
)
from starlette.responses import RedirectResponse  # noqa: E402,F811


def flask_direct():
    # ruleid: python-pii-in-url
    return flask.redirect(user.email)


def flask_url_for_direct():
    # ruleid: python-pii-in-url
    return flask.url_for("profile", email=user.email)


def bare_direct():
    # ruleid: python-pii-in-url
    return redirect(user.email)


def bare_keyword():
    # ruleid: python-pii-in-url
    return redirect(location=user.email)


def bare_fstring():
    # ruleid: python-pii-in-url
    return redirect(f"/u/{user.email}")


def bare_concat():
    # ruleid: python-pii-in-url
    return redirect("/u/" + user.email)


def bare_percent():
    # ruleid: python-pii-in-url
    return redirect("/u/%s" % user.email)


def bare_format():
    # ruleid: python-pii-in-url
    return redirect("/u/{}".format(user.email))


def bare_local():
    contact = user.phone
    # ruleid: python-pii-in-url
    return redirect(contact)


def bare_param(email):
    # ruleid: python-pii-in-url
    return redirect(email)


def bare_key(data):
    # ruleid: python-pii-in-url
    return redirect(data["email"])


def bare_suffix():
    # ruleid: python-pii-in-url
    return redirect(user.phone_number)


def bare_first():
    # ruleid: python-pii-in-url
    return redirect(user.first_name)


def bare_body():
    # ruleid: python-pii-in-url
    return redirect(req.body)


def bare_multiline():
    # ruleid: python-pii-in-url
    return redirect(
        user.email)


def link_keyword():
    # ruleid: python-pii-in-url
    return url_for("profile", email=user.email)


def link_extra_param():
    # ruleid: python-pii-in-url
    return url_for("profile", next=user.phone)


def link_fstring():
    # ruleid: python-pii-in-url
    return url_for("profile", email=f"{user.email}")


def link_local():
    contact = user.email
    # ruleid: python-pii-in-url
    return url_for("profile", email=contact)


def link_verified():
    # ruleid: python-pii-in-url
    return url_for("profile", email=user.emailVerified)


def link_key(data):
    # ruleid: python-pii-in-url
    return url_for("profile", email=data["email"])


def django_direct():
    # ruleid: python-pii-in-url
    return HttpResponseRedirect(user.email)


def django_percent():
    # ruleid: python-pii-in-url
    return HttpResponseRedirect("/u/%s" % user.email)


def django_last4():
    # ruleid: python-pii-in-url
    return HttpResponseRedirect(user.ssn_last4)


def django_permanent():
    # ruleid: python-pii-in-url
    return HttpResponsePermanentRedirect(redirect_to=user.email)


def starlette_direct():
    # ruleid: python-pii-in-url
    return RedirectResponse(user.email)


def starlette_format():
    # ruleid: python-pii-in-url
    return RedirectResponse("/u/{}".format(user.email))


def starlette_keyword():
    # ruleid: python-pii-in-url
    return RedirectResponse(url=user.email)


def starlette_headers():
    # ruleid: python-pii-in-url
    return RedirectResponse(request.headers)


def opaque_id():
    # ok: python-pii-in-url
    return redirect(user.id)


def opaque_id_var(user_id):
    # ok: python-pii-in-url
    return redirect(user_id)


def constant_path():
    # ok: python-pii-in-url
    return redirect("/home")


def slug_path(slug):
    # ok: python-pii-in-url
    return redirect(slug)


def link_opaque_id():
    # ok: python-pii-in-url
    return url_for("profile", user_id=user.id)


def link_constant():
    # ok: python-pii-in-url
    return url_for("home")


def redacted():
    # ok: python-pii-in-url
    return redirect(redact(user.email))


def masked():
    # ok: python-pii-in-url
    return url_for("profile", email=mask(user.email))


def hashed():
    # ok: python-pii-in-url
    return HttpResponseRedirect(hash(user.email))


def tokenized():
    # ok: python-pii-in-url
    return RedirectResponse(tokenize(user.email))


def counted():
    # ok: python-pii-in-url
    return redirect(len(user.email))


def checked():
    # ok: python-pii-in-url
    return redirect(bool(user.email))


def typed():
    # ok: python-pii-in-url
    return redirect(type(user.email))


def compared():
    # ok: python-pii-in-url
    return redirect(user.email is not None)


def compared_link(other):
    # ok: python-pii-in-url
    return url_for("profile", check=user.email == other)


def allow_count():
    # ok: python-pii-in-url
    return redirect(email_count)


def allow_host():
    # ok: python-pii-in-url
    return redirect(settings.EMAIL_HOST)


def allow_pattern():
    # ok: python-pii-in-url
    return url_for("profile", pat=ssn_pattern)


def allow_domain():
    # ok: python-pii-in-url
    return redirect(user.email_domain)


def allow_phone_type():
    # ok: python-pii-in-url
    return redirect(phone_type)


def plural():
    # ok: python-pii-in-url
    return redirect(user.emails)


def run_together():
    # ok: python-pii-in-url
    return redirect(useremail)


def module_attr():
    # ok: python-pii-in-url
    return redirect(email.header)


def pii_elsewhere():
    send(user.email)
    # ok: python-pii-in-url
    return redirect("/home")


def pii_elsewhere_link():
    notify(user.email)
    # ok: python-pii-in-url
    return url_for("home")
