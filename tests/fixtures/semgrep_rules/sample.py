class User:
    email = "foo@example.com"


user = User()
# ruleid: sample-raw-pii-logging
print(user.email)
# ok: sample-raw-pii-logging
print("hello")
