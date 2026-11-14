# ruleid: python-pii-to-telemetry
sentry_sdk.set_user({"email": user.email})
# ruleid: python-pii-to-telemetry
sentry_sdk.set_context("user", {"email": user.email})
# ruleid: python-pii-to-telemetry
sentry_sdk.set_tag("email", user.email)
# ruleid: python-pii-to-telemetry
sentry_sdk.set_tags({"email": user.email})
# ruleid: python-pii-to-telemetry
sentry_sdk.set_extra("email", user.email)
# ruleid: python-pii-to-telemetry
sentry_sdk.add_breadcrumb(category="auth", data={"phone": user.phone})
# ruleid: python-pii-to-telemetry
sentry_sdk.capture_message(f"signup {user.email}")
# ruleid: python-pii-to-telemetry
sentry_sdk.capture_event({"user": {"ssn": user.ssn}})
# ruleid: python-pii-to-telemetry
sentry_sdk.set_tag("email", f"{user.email}")
# ruleid: python-pii-to-telemetry
analytics.identify(user.id, traits={"email": user.email})
# ruleid: python-pii-to-telemetry
analytics.track("signup", {"email": user.email})
# ruleid: python-pii-to-telemetry
analytics.page("home", {"email": user.email})
# ruleid: python-pii-to-telemetry
analytics.screen("home", {"email": user.email})
# ruleid: python-pii-to-telemetry
analytics.group("org", {"email": user.email})
# ruleid: python-pii-to-telemetry
analytics.alias(user.id, user.email)
# ruleid: python-pii-to-telemetry
posthog.capture("signup", properties={"email": user.email})
# ruleid: python-pii-to-telemetry
posthog.identify(user.id, properties={"email": user.email})
# ruleid: python-pii-to-telemetry
posthog.set(user.id, {"email": user.email})
# ruleid: python-pii-to-telemetry
posthog.set_once(user.id, {"email": user.email})
# ruleid: python-pii-to-telemetry
posthog.alias(user.id, user.email)
# ruleid: python-pii-to-telemetry
posthog.group_identify("org", {"email": user.email})
# ruleid: python-pii-to-telemetry
tracer.current_span().set_tag("email", user.email)
# ruleid: python-pii-to-telemetry
tracer.current_span().set_tags({"email": user.email})
# ruleid: python-pii-to-telemetry
ddtrace.tracer.current_span().set_tag("email", user.email)
# ruleid: python-pii-to-telemetry
ddtrace.tracer.current_span().set_tags({"email": user.email})
# ruleid: python-pii-to-telemetry
sentry_sdk.set_user({"phone": user.phone_number})
# ruleid: python-pii-to-telemetry
analytics.identify(user.id, traits={"verified": user.emailVerified})
value = user.email
# ruleid: python-pii-to-telemetry
sentry_sdk.set_user({"email": value})
# ruleid: python-pii-to-telemetry
analytics.track("signup", "hi " + user.email)
# ruleid: python-pii-to-telemetry
sentry_sdk.set_user(
    {"email": user.email})


def posthog_client_calls():
    client = Posthog("key")
    # ruleid: python-pii-to-telemetry
    client.capture("signup", properties={"email": user.email})
    # ruleid: python-pii-to-telemetry
    client.identify(user.id, properties={"email": user.email})
    # ruleid: python-pii-to-telemetry
    client.set(user.id, {"email": user.email})
    # ruleid: python-pii-to-telemetry
    client.set_once(user.id, {"email": user.email})
    # ruleid: python-pii-to-telemetry
    client.alias(user.id, user.email)
    # ruleid: python-pii-to-telemetry
    client.group_identify("org", {"email": user.email})


def span_calls():
    span = tracer.current_span()
    # ruleid: python-pii-to-telemetry
    span.set_tag("email", user.email)
    # ruleid: python-pii-to-telemetry
    span.set_tags({"phone": user.phone})


def trace_calls():
    span = tracer.trace("op")
    # ruleid: python-pii-to-telemetry
    span.set_tag("email", user.email)
    # ruleid: python-pii-to-telemetry
    span.set_tags({"email": user.email})


# ok: python-pii-to-telemetry
sentry_sdk.set_user({"id": user.id})
# ok: python-pii-to-telemetry
analytics.identify(user_id)
# ok: python-pii-to-telemetry
analytics.identify(user.id)
# ok: python-pii-to-telemetry
sentry_sdk.set_tag("env", "prod")
# ok: python-pii-to-telemetry
analytics.track(user.id, "signup")
# ok: python-pii-to-telemetry
sentry_sdk.set_user({"email": redact(user.email)})
# ok: python-pii-to-telemetry
posthog.capture("signup", properties={"email": hash(user.email)})
# ok: python-pii-to-telemetry
sentry_sdk.set_tag("n", len(user.email))
# ok: python-pii-to-telemetry
analytics.track("click", {"n": item.count})
# ok: python-pii-to-telemetry
posthog.capture("signup", "user signed up")
# ok: python-pii-to-telemetry
sentry_sdk.capture_message(user.email is None)
# ok: python-pii-to-telemetry
sentry_sdk.capture_event(user.email == other)
# ok: python-pii-to-telemetry
sentry_sdk.capture_message(email.utils.formatdate())
# ok: python-pii-to-telemetry
analytics.track("click", {"n": email_count})
# ok: python-pii-to-telemetry
sentry_sdk.set_tag("host", settings.EMAIL_HOST)
# ok: python-pii-to-telemetry
posthog.capture("event", properties={"p": ssn_pattern})
# ok: python-pii-to-telemetry
sentry_sdk.set_extra("kind", user.phone_type)
# ok: python-pii-to-telemetry
analytics.identify(user_id, traits={"e": user.email_domain})
# ok: python-pii-to-telemetry
posthog.capture("event", properties=emails)
# ok: python-pii-to-telemetry
analytics.page("home", {"e": useremail})
# ok: python-pii-to-telemetry
cache.set("email", user.email)
# ok: python-pii-to-telemetry
metrics.capture("event", {"email": user.email})
# ok: python-pii-to-telemetry
widget.set_tag("email", user.email)
# ok: python-pii-to-telemetry
other.identify(user.id, traits={"email": user.email})


def unassigned_client_call():
    client = make_client()
    # ok: python-pii-to-telemetry
    client.capture("signup", properties={"email": user.email})


def unassigned_span_call():
    span = get_span()
    # ok: python-pii-to-telemetry
    span.set_tag("email", user.email)
