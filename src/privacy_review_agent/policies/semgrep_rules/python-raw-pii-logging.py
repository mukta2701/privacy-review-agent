# ruleid: python-raw-pii-logging
print(user.email)
# ruleid: python-raw-pii-logging
logger.info(f"login {user.email}")
# ruleid: python-raw-pii-logging
logger.warning("email=" + user.email)
msg = user.phone
# ruleid: python-raw-pii-logging
logger.error(msg)
# ruleid: python-raw-pii-logging
logger.info(
    user.email
)
# ruleid: python-raw-pii-logging
print(user.phone_number)
# ruleid: python-raw-pii-logging
print(req.body)
# ruleid: python-raw-pii-logging
logging.info(request.headers)
# ok: python-raw-pii-logging
logger.info(redact(user.email))
# ok: python-raw-pii-logging
logger.info(util.mask(user.email))
# ok: python-raw-pii-logging
print(request_id)
# ok: python-raw-pii-logging
logger.warning("user email not found")
# ok: python-raw-pii-logging
save(user.email)
# ok: python-raw-pii-logging
# user email must never be logged
logger.info("done")
