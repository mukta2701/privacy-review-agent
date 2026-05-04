import requests


class User:
    email = "foo@example.com"


user = User()
requests.post("https://analytics.example.com/collect", json={"email": user.email})
