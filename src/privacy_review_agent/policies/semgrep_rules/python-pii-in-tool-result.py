# Near-misses without a qualifying import go above the
# `from langchain_core.tools import tool` line: the import must precede the
# function for `@tool` to count.


@tool
def early_no_import():
    # ok: python-pii-in-tool-result
    return user.email


@tool("early")
def early_named_no_import():
    # ok: python-pii-in-tool-result
    return user.email


def plain():
    # ok: python-pii-in-tool-result
    return user.email


@app.route("/x")
def routed():
    # ok: python-pii-in-tool-result
    return user.email


class Widget:
    @property
    def address(self):
        # ok: python-pii-in-tool-result
        return self.email


@pytest.fixture
def user_record():
    # ok: python-pii-in-tool-result
    return user.email


@registry.tool
def registry_tool():
    # ok: python-pii-in-tool-result
    return user.email


@server.tool()
def server_tool():
    # ok: python-pii-in-tool-result
    return user.email


# Mid-file import is the `@tool` import gate under test: the near-misses
# above it stay silent.
from langchain_core.tools import tool  # noqa: E402


@mcp.tool
def get_email():
    # ruleid: python-pii-in-tool-result
    return user.email


@mcp.tool()
def get_email_call():
    # ruleid: python-pii-in-tool-result
    return user.email


@function_tool
def lookup():
    # ruleid: python-pii-in-tool-result
    return {"email": user.email}


@function_tool(name_override="lookup_user")
def lookup_named():
    contact = user.phone
    # ruleid: python-pii-in-tool-result
    return contact


@mcp.tool
async def get_email_async():
    # ruleid: python-pii-in-tool-result
    return f"hi {user.phone}"


@app.route("/x")
@tool
def routed_tool():
    # ruleid: python-pii-in-tool-result
    return user.email


@tool
def direct_tool():
    # ruleid: python-pii-in-tool-result
    return user.email


@tool("named")
def named_tool():
    # ruleid: python-pii-in-tool-result
    return [user.ssn]


@mcp.tool
def param_tool(email):
    # ruleid: python-pii-in-tool-result
    return email


@mcp.tool
def body_tool():
    # ruleid: python-pii-in-tool-result
    return req.body


@mcp.tool
def name_tool():
    # ruleid: python-pii-in-tool-result
    return user.first_name


@mcp.tool
def conditional_tool(flag):
    if flag:
        # ruleid: python-pii-in-tool-result
        return user.email
    # ok: python-pii-in-tool-result
    return "none"


@mcp.tool
def loop_tool(items):
    for item in items:
        # ruleid: python-pii-in-tool-result
        return user.email
    # ok: python-pii-in-tool-result
    return "none"


@mcp.tool
def outer_tool():
    def inner():
        # ok: python-pii-in-tool-result
        return user.email

    # ruleid: python-pii-in-tool-result
    return user.phone


@mcp.tool
def nested_silent_tool():
    def inner():
        # ok: python-pii-in-tool-result
        return user.email

    # ok: python-pii-in-tool-result
    return 1


@mcp.tool
def internal_use_tool():
    send(user.email)
    # ok: python-pii-in-tool-result
    return "sent"


@mcp.tool
def redacted_tool():
    # ok: python-pii-in-tool-result
    return redact(user.email)


@mcp.tool
def counted_tool():
    # ok: python-pii-in-tool-result
    return len(user.email)


@mcp.tool
def bool_tool():
    # ok: python-pii-in-tool-result
    return bool(user.email)


@mcp.tool
def compared_tool():
    # ok: python-pii-in-tool-result
    return user.email is not None


@mcp.tool
def opaque_tool():
    # ok: python-pii-in-tool-result
    return user.id


@mcp.tool
def count_tool():
    # ok: python-pii-in-tool-result
    return email_count


@mcp.tool
def host_tool():
    # ok: python-pii-in-tool-result
    return settings.EMAIL_HOST


@mcp.tool
def pattern_tool():
    # ok: python-pii-in-tool-result
    return ssn_pattern


@mcp.tool
def domain_tool():
    # ok: python-pii-in-tool-result
    return user.email_domain


@mcp.tool
def run_together_tool():
    # ok: python-pii-in-tool-result
    return useremail


@function_tool
def compared_function_tool():
    # ok: python-pii-in-tool-result
    return user.email == other
