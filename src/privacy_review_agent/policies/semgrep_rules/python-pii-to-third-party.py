import httpx
import requests

# ruleid: python-pii-to-third-party
requests.post("https://api.example.com/x", json={"e": user.email})
# ruleid: python-pii-to-third-party
requests.get("https://api.example.com/x", params={"phone": user.phone})
# ruleid: python-pii-to-third-party
requests.put("https://api.example.com/x", data={"ssn": user.ssn})
# ruleid: python-pii-to-third-party
requests.patch("https://api.example.com/x", data="hi " + user.email)
# ruleid: python-pii-to-third-party
requests.delete("https://api.example.com/x", headers=request.headers)
# ruleid: python-pii-to-third-party
requests.request("GET", "https://api.example.com/x", params={"n": user.first_name})
# ruleid: python-pii-to-third-party
httpx.post("https://api.example.com/x", json={"e": user.email})
# ruleid: python-pii-to-third-party
httpx.get("https://api.example.com/x", params=f"phone={user.phone}")
# ruleid: python-pii-to-third-party
httpx.request("POST", "https://api.example.com/x", json={"e": user.email})
# ruleid: python-pii-to-third-party
requests.post("https://api.example.com/x", json="hi {}".format(user.email))
# ruleid: python-pii-to-third-party
requests.post("https://api.example.com/x", json="hi %s" % user.email)
# ruleid: python-pii-to-third-party
requests.post("https://api.example.com/x", content=user.email)
payload = {"e": user.email}
# ruleid: python-pii-to-third-party
requests.post("https://api.example.com/x", json=payload)
# ruleid: python-pii-to-third-party
requests.post(
    "https://api.example.com/x", json={"e": user.email})
# ruleid: python-pii-to-third-party
httpx.post("https://api.example.com/x", json={"e": user.last_name})
# ruleid: python-pii-to-third-party
requests.post("https://api.example.com/x", json={"e": user.phone_number})
# ruleid: python-pii-to-third-party
requests.post("https://api.example.com/x", json={"e": user.emailVerified})


def make_session_calls():
    s = requests.Session()
    # ruleid: python-pii-to-third-party
    s.post("https://api.example.com/x", json={"e": user.email})
    # ruleid: python-pii-to-third-party
    s.get("https://api.example.com/x", params={"phone": user.phone})


def make_client_calls():
    c = httpx.Client()
    # ruleid: python-pii-to-third-party
    c.put("https://api.example.com/x", data={"ssn": user.ssn})


async def make_async_calls():
    c = httpx.AsyncClient()
    # ruleid: python-pii-to-third-party
    await c.post("https://api.example.com/x", json={"e": user.email})


# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", json={"e": redact(user.email)})
# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", json={"e": hash(user.email)})
# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", json={"id": user.id})
# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", json={"e": "none"})
# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", data=email.utils.formatdate())
# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", json=(user.email is None))
# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", json=(user.email == other))
# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", json={"n": email_count})
# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", json=settings.EMAIL_HOST)
# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", json={"p": ssn_pattern})
# ok: python-pii-to-third-party
requests.post("https://api.example.com/x", json=len(user.email))
other = make()
# ok: python-pii-to-third-party
other.post("https://api.example.com/x", json={"e": user.email})
# ok: python-pii-to-third-party
Model.objects.post("https://api.example.com/x", email=user.email)
# ok: python-pii-to-third-party
httpx.post("https://api.example.com/x", json={"e": user.email_count})
# ok: python-pii-to-third-party
httpx.post("https://api.example.com/x", json={"e": user.email_domain})
# ok: python-pii-to-third-party
httpx.post("https://api.example.com/x", json={"e": user.phone_type})
# ok: python-pii-to-third-party
httpx.post("https://api.example.com/x", json=emails)
# ok: python-pii-to-third-party
httpx.post("https://api.example.com/x", json=useremail)


def make_clean_session_call():
    s = requests.Session()
    # ok: python-pii-to-third-party
    s.post("https://api.example.com/x", json={"a": 1})
