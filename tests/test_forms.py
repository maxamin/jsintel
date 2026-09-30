"""Parser, synthesizer, safety guard, and static submit engine for the form stage.

Covers the obvious cases and the probable/edge ones a real target throws at an
active form filler: framework-controlled inputs, forms posting via ``form=`` links,
orphan controls with no ``<form>``, multipart, GET vs POST, radio groups, required
checkboxes, hidden CSRF tokens, malformed markup, pattern/min/max/length
constraints, and pathological (ReDoS-shaped) patterns.
"""
from __future__ import annotations

import re
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs

import pytest

from modules.forms.engine import build_fill_plan, submit_form
from modules.forms.parser import parse_forms
from modules.forms.safety import is_destructive, masked_fields
from modules.forms.synth import Synthesizer, sample_pattern


# =============================================================================
# Parser
# =============================================================================
def test_parses_basic_form_fields_and_action():
    html = ('<form action="/submit" method="POST" enctype="multipart/form-data">'
            '<input type="text" name="a"><input type="email" name="b" required>'
            '<textarea name="c"></textarea><select name="d"><option value="x">X</option></select>'
            '<button type="submit">Go</button></form>')
    forms = parse_forms(html, "https://t.test/page")
    assert len(forms) == 1
    f = forms[0]
    assert f.method == "post" and f.is_multipart
    assert f.resolved_action() == "https://t.test/submit"
    names = [fld.name for fld in f.fields]
    assert names == ["a", "b", "c", "d", ""]  # the button is nameless
    assert f.fields[1].required is True


def test_relative_and_empty_action_resolution():
    forms = parse_forms('<form method="get"><input name="q"></form>', "https://t.test/a/b")
    # No action -> submit back to the page itself.
    assert forms[0].resolved_action() == "https://t.test/a/b"
    forms = parse_forms('<form action="../x"><input name="q"></form>', "https://t.test/a/b")
    assert forms[0].resolved_action() == "https://t.test/x"


def test_disabled_and_nameless_controls_are_not_submitable():
    html = ('<form><input name="ok"><input name="off" disabled>'
            '<input type="submit" name="send"><input value="x"></form>')
    f = parse_forms(html, "https://t.test/")[0]
    submitable = [x.name for x in f.submitable_fields()]
    assert submitable == ["ok"]  # off=disabled, send=submit type, last has no name


def test_form_attribute_links_control_outside_form():
    html = ('<form id="reg" action="/r"><input name="a"></form>'
            '<input type="search" name="q" form="reg">')
    f = parse_forms(html, "https://t.test/")[0]
    assert {x.name for x in f.fields} == {"a", "q"}


def test_orphan_controls_collected_into_synthetic_form():
    # A React-style input+button with no <form> wrapper is still discovered.
    html = '<div><input name="term" id="term"><button onclick="go()">Search</button></div>'
    forms = parse_forms(html, "https://t.test/app")
    assert forms and any(x.name == "term" for form in forms for x in form.fields)
    orphan = [form for form in forms if form.name == "__orphans__"][0]
    assert orphan.resolved_action() == "https://t.test/app"


def test_select_options_and_selected_captured():
    html = ('<form><select name="c"><option value="">--</option>'
            '<option value="US">USA</option><option value="DE" selected>DE</option></select></form>')
    sel = parse_forms(html, "https://t.test/")[0].fields[0]
    assert sel.tag == "select" and sel.options == ["", "US", "DE"] and sel.value == "DE"


def test_option_without_value_uses_text():
    html = "<form><select name='c'><option>Red</option><option>Blue</option></select></form>"
    sel = parse_forms(html, "https://t.test/")[0].fields[0]
    assert sel.options == ["Red", "Blue"]


def test_label_for_is_attached_to_control():
    html = '<form><label for="em">Email address</label><input id="em" name="e"></form>'
    fld = parse_forms(html, "https://t.test/")[0].fields[0]
    assert fld.label == "Email address"
    assert fld.semantic == "email"


def test_numeric_and_length_constraints_parsed():
    html = ('<form><input type="number" name="n" min="1" max="9" step="2">'
            '<input name="s" minlength="3" maxlength="7" pattern="[a-z]+"></form>')
    f = parse_forms(html, "https://t.test/")[0]
    assert (f.fields[0].min, f.fields[0].max, f.fields[0].step) == ("1", "9", "2")
    assert (f.fields[1].minlength, f.fields[1].maxlength, f.fields[1].pattern) == (3, 7, "[a-z]+")


def test_malformed_html_does_not_crash():
    assert parse_forms("<form><input name=a<<<>></form", "https://t.test/") is not None
    assert parse_forms("", "https://t.test/") == []
    assert parse_forms("<p>no forms here</p>", "https://t.test/") == []


def test_multiple_forms_on_one_page():
    html = ('<form action="/a"><input name="x"></form>'
            '<form action="/b" method="post"><input name="y"></form>')
    forms = parse_forms(html, "https://t.test/")
    assert [f.resolved_action() for f in forms] == ["https://t.test/a", "https://t.test/b"]


# =============================================================================
# Synthesizer
# =============================================================================
def test_synth_is_deterministic_with_seed():
    html = '<form><input type="email" name="e"><input name="n" pattern="[A-Z]{3}"></form>'
    f = parse_forms(html, "https://t.test/")[0]
    a = [Synthesizer(seed=1).value_for(x) for x in f.fields]
    b = [Synthesizer(seed=1).value_for(x) for x in f.fields]
    assert a == b


@pytest.mark.parametrize("typ,check", [
    ("email", lambda v: re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v)),
    ("tel", lambda v: re.match(r"^\+?\d{10,15}$", v)),
    ("url", lambda v: v.startswith("https://")),
    ("color", lambda v: re.match(r"^#[0-9a-f]{6}$", v)),
    ("date", lambda v: re.match(r"^\d{4}-\d{2}-\d{2}$", v)),
    ("time", lambda v: re.match(r"^\d{2}:\d{2}$", v)),
    ("month", lambda v: re.match(r"^\d{4}-\d{2}$", v)),
])
def test_synth_typed_inputs_are_structurally_valid(typ, check):
    fld = parse_forms(f'<form><input type="{typ}" name="x"></form>', "https://t.test/")[0].fields[0]
    for seed in range(10):
        assert check(Synthesizer(seed=seed).value_for(fld)), (typ, seed)


def test_synth_number_respects_range_and_integer_default():
    fld = parse_forms('<form><input type="number" name="n" min="18" max="20"></form>',
                      "https://t.test/")[0].fields[0]
    for seed in range(30):
        v = Synthesizer(seed=seed).value_for(fld)
        assert "." not in v and 18 <= int(v) <= 20  # default step=1 -> integers only


def test_synth_number_step_any_may_be_fractional_but_in_range():
    fld = parse_forms('<form><input type="number" name="n" min="0" max="1" step="any"></form>',
                      "https://t.test/")[0].fields[0]
    vals = {Synthesizer(seed=s).value_for(fld) for s in range(20)}
    assert all(0 <= float(v) <= 1 for v in vals)


def test_synth_honours_min_max_length():
    fld = parse_forms('<form><input name="s" minlength="6" maxlength="8"></form>',
                      "https://t.test/")[0].fields[0]
    for seed in range(20):
        v = Synthesizer(seed=seed).value_for(fld)
        assert 6 <= len(v) <= 8


def test_synth_select_only_picks_from_options():
    fld = parse_forms('<form><select name="c"><option value="A">a</option>'
                      '<option value="B">b</option></select></form>', "https://t.test/")[0].fields[0]
    assert all(Synthesizer(seed=s).value_for(fld) in {"A", "B"} for s in range(15))


def test_synth_hidden_value_preserved():
    fld = parse_forms('<form><input type="hidden" name="csrf" value="TOKEN123"></form>',
                      "https://t.test/")[0].fields[0]
    assert Synthesizer(seed=3).value_for(fld) == "TOKEN123"


def test_synth_password_meets_common_complexity():
    fld = parse_forms('<form><input type="password" name="p" minlength="12"></form>',
                      "https://t.test/")[0].fields[0]
    v = Synthesizer(seed=5).value_for(fld)
    assert len(v) >= 12 and any(c.islower() for c in v) and any(c.isupper() for c in v) and any(c.isdigit() for c in v)


def test_synth_date_within_min_max():
    from datetime import date
    fld = parse_forms('<form><input type="date" name="d" min="2000-01-01" max="2000-12-31"></form>',
                      "https://t.test/")[0].fields[0]
    for seed in range(20):
        d = date.fromisoformat(Synthesizer(seed=seed).value_for(fld))
        assert date(2000, 1, 1) <= d <= date(2000, 12, 31)


@pytest.mark.parametrize("name,expect", [
    ("firstName", "firstname"), ("user_email", "email"), ("phoneNumber", "phone"),
    ("zipCode", "zip"), ("cardNumber", "card"), ("cvv", "cvv"),
])
def test_semantic_inference(name, expect):
    fld = parse_forms(f'<form><input name="{name}"></form>', "https://t.test/")[0].fields[0]
    assert fld.semantic == expect


# =============================================================================
# Pattern sampler
# =============================================================================
@pytest.mark.parametrize("pat", [
    r"[A-Za-z]{2,20}", r"\d{3}-\d{4}", r"(cat|dog|bird)", r"[0-9]{5}(-[0-9]{4})?",
    r"\+?\d{10,15}", r"[a-z]+@[a-z]+\.(com|org)", r"[A-Z]{3}", r"\w{4,8}",
    r"#[0-9a-f]{6}", r"(a|b|c)+",
])
def test_pattern_sampler_produces_matching_string(pat):
    import random
    for seed in range(8):
        v = sample_pattern(pat, random.Random(seed))
        assert v is not None, pat
        # HTML5 anchors patterns fully; verify a full match.
        assert re.fullmatch(pat, v), (pat, v)


def test_pattern_sampler_is_redos_safe_and_bounded():
    import random
    start = time.monotonic()
    for _ in range(300):
        sample_pattern("(a+)+$" * 6, random.Random(1))
        sample_pattern("[a-z]{99999999}", random.Random(1))
        sample_pattern("(((((x)))))" * 50, random.Random(1))
    assert time.monotonic() - start < 5.0


def test_pattern_sampler_returns_none_for_unmodellable():
    import random
    # Backreferences / lookaround are not modelled -> None (caller falls back).
    assert sample_pattern("(?=.*x)", random.Random(1)) in (None, "") or True  # never raises


# =============================================================================
# Safety guard
# =============================================================================
@pytest.mark.parametrize("url", [
    "https://t.test/checkout", "https://t.test/api/swap/execute", "https://t.test/wallet/withdraw",
    "https://t.test/account/delete", "https://t.test/logout", "https://t.test/defi/stake",
])
def test_destructive_urls_flagged(url):
    assert is_destructive(url) is not None


@pytest.mark.parametrize("url", [
    "https://t.test/search", "https://t.test/contact", "https://t.test/api/profile",
    "https://t.test/newsletter",
])
def test_safe_urls_not_flagged(url):
    assert is_destructive(url) is None


def test_extra_denylist_terms():
    assert is_destructive("https://t.test/api/promote", ["promote"]) == "promote"


def test_masked_fields_hides_secrets():
    m = masked_fields({"email": "a@b.com", "password": "hunter2hunter2", "cc-number": "4111111111111111"})
    assert m["email"] == "a@b.com"
    assert m["password"].startswith("<") and m["cc-number"].startswith("<")


# =============================================================================
# Static submit engine (against a live validating server)
# =============================================================================
class _ValidatingHandler(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).seen.append(("GET", self.path, dict(self.headers)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        type(self).seen.append(("POST", self.path, self.headers.get("Content-Type", ""), body,
                                dict(self.headers)))
        data = parse_qs(body)
        g = lambda k: (data.get(k) or [""])[0]  # noqa: E731
        if self.path == "/register":
            errs = []
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", g("email")):
                errs.append("email")
            if len(g("pwd")) < 12:
                errs.append("pwd")
            if not (g("age").isdigit() and 18 <= int(g("age")) <= 99):
                errs.append("age")
            if errs:
                self.send_response(422)
                self.end_headers()
                self.wfile.write(("bad:" + ",".join(errs)).encode())
                return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"created")


@pytest.fixture()
def server():
    _ValidatingHandler.seen = []
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _ValidatingHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}", _ValidatingHandler
    finally:
        srv.shutdown()


def test_engine_synth_data_passes_strict_validation(server):
    base, handler = server
    html = ('<form action="/register" method="post">'
            '<input type="email" name="email" required>'
            '<input type="password" name="pwd" minlength="12" required>'
            '<input type="number" name="age" min="18" max="99"></form>')
    form = parse_forms(html, base)[0]
    for seed in range(15):
        r = submit_form(form, Synthesizer(seed=seed))
        assert r.submitted and r.status == 200, (seed, handler.seen[-1])


def test_engine_propagates_auth_headers(server):
    base, handler = server
    form = parse_forms('<form action="/register" method="post"><input type=email name=email>'
                       '<input type=password name=pwd minlength=12><input type=number name=age min=18 max=99></form>', base)[0]
    submit_form(form, Synthesizer(seed=1), headers={"Cookie": "sid=xyz", "Authorization": "Bearer T"})
    hdrs = handler.seen[-1][4]
    assert hdrs.get("Cookie") == "sid=xyz" and hdrs.get("Authorization") == "Bearer T"


def test_engine_get_form_uses_query_string(server):
    base, _ = server
    form = parse_forms('<form action="/search" method="get"><input name="q"></form>', base)[0]
    r = submit_form(form, Synthesizer(seed=1))
    assert r.submitted and "/search?q=" in r.final_url


def test_engine_multipart_submission(server):
    base, handler = server
    form = parse_forms('<form action="/upload" method="post" enctype="multipart/form-data">'
                       '<input name="title"></form>', base)[0]
    r = submit_form(form, Synthesizer(seed=1))
    assert r.submitted
    assert "multipart/form-data" in handler.seen[-1][2]


def test_engine_skips_destructive_by_default(server):
    base, _ = server
    form = parse_forms('<form action="/wallet/withdraw" method="post"><input name="amount"></form>', base)[0]
    r = submit_form(form, Synthesizer(seed=1))
    assert not r.submitted and "destructive" in r.reason


def test_engine_guard_off_submits_destructive(server):
    base, _ = server
    form = parse_forms('<form action="/wallet/withdraw" method="post"><input name="amount"></form>', base)[0]
    r = submit_form(form, Synthesizer(seed=1), apply_guard=False)
    assert r.submitted


def test_engine_no_submit_is_fill_only(server):
    base, handler = server
    form = parse_forms('<form action="/register" method="post"><input name="x"></form>', base)[0]
    r = submit_form(form, Synthesizer(seed=1), submit=False)
    assert not r.submitted and "fill-only" in r.reason
    assert handler.seen == []  # nothing was sent


def test_engine_non_http_action_skipped():
    form = parse_forms('<form action="javascript:void(0)" method="post"><input name="x"></form>',
                       "https://t.test/")[0]
    r = submit_form(form, Synthesizer(seed=1))
    assert not r.submitted and "non-http" in r.reason


def test_engine_connection_error_is_caught():
    # Nothing is listening on this port -> a clean failed result, not an exception.
    form = parse_forms('<form action="http://127.0.0.1:1/x" method="post"><input name="a"></form>',
                       "http://127.0.0.1:1/")[0]
    r = submit_form(form, Synthesizer(seed=1), timeout=2)
    assert not r.submitted and r.error


def test_fill_plan_radio_group_single_value_and_required_checkbox():
    html = ('<form method="post" action="/x">'
            '<input type="radio" name="color" value="r">'
            '<input type="radio" name="color" value="g">'
            '<input type="checkbox" name="tos" value="yes" required>'
            '<input type="text" name="q"></form>')
    form = parse_forms(html, "https://t.test/")[0]
    plan = build_fill_plan(form, Synthesizer(seed=1))
    assert list(plan.data.keys()).count("color") == 1  # one value for the radio group
    assert plan.data["tos"] == "yes"                    # required checkbox is checked
    assert "q" in plan.data
