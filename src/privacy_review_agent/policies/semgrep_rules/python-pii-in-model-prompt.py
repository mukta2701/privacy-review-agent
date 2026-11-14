# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=[{"role": "user", "content": user.email}])
# ruleid: python-pii-in-model-prompt
client.responses.create(model=m, input=user.phone)
# ruleid: python-pii-in-model-prompt
client.messages.create(model=m, max_tokens=1, messages=[{"role": "user", "content": f"hi {user.email}"}])
# ruleid: python-pii-in-model-prompt
model.generate_content(user.ssn)
# ruleid: python-pii-in-model-prompt
client.models.generate_content(model=m, contents=user.first_name)
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=f"hi {user.email}")
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages="hi {}".format(user.email))
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages="hi %s" % user.email)
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages="hi " + user.email)
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages="".join(["hi ", user.email]))
prompt = user.email
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=prompt)
msgs = [{"role": "user", "content": user.email}]
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=msgs)
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, system=user.email)
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, prompt=user.email)
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=[{"role": "system", "content": user.last_name}])
# ruleid: python-pii-in-model-prompt
client.chat.completions.stream(model=m, messages=[{"role": "user", "content": user.email}])
# ruleid: python-pii-in-model-prompt
client.beta.chat.completions.parse(model=m, messages=[{"role": "user", "content": user.email}])
# ruleid: python-pii-in-model-prompt
client.responses.stream(model=m, input=user.email)
# ruleid: python-pii-in-model-prompt
client.completions.create(model=m, prompt=user.email)
# ruleid: python-pii-in-model-prompt
client.messages.stream(model=m, messages=[{"role": "user", "content": user.email}])
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=user.phone_number)
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=user.email_address)
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=user.ssn_last4)
# ruleid: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=user.emailVerified)


def make_send_calls():
    chat = model.start_chat()
    # ruleid: python-pii-in-model-prompt
    chat.send_message(user.email)


def make_chats_calls():
    chat = client.chats.create(model=m)
    # ruleid: python-pii-in-model-prompt
    chat.send_message(user.email)


async def make_async_calls():
    # ruleid: python-pii-in-model-prompt
    await client.chat.completions.create(model=m, messages=[{"role": "user", "content": user.email}])
# ok: python-pii-in-model-prompt
bot.send_message(chat_id, user.email)
other = make_bot()
# ok: python-pii-in-model-prompt
other.send_message(user.email)
# ok: python-pii-in-model-prompt
client.messages.create(to=user.phone, body="hi")
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=[{"role": "user", "content": user.id}])
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=email_count)
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=settings.EMAIL_HOST)
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=ssn_pattern)
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=redact(user.email))
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=util.mask(user.email))
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=hash(user.email))
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=tokenize(user.email))
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=len(user.email))
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=bool(user.email))
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=type(user.email))
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=(user.email is None))
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=(user.email == other))
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=email.utils.formatdate())
# ok: python-pii-in-model-prompt
Model.objects.create(email=user.email)
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=user.email_count)
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=user.email_domain)
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=user.phone_type)
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=emails)
# ok: python-pii-in-model-prompt
client.chat.completions.create(model=m, messages=useremail)
pending = user.email
