"""Static (``requests``-based) form filler & submitter.

Given a parsed :class:`Form`, synthesize a spec-valid value for every control and
submit it to the form's ``action`` with the form's declared method/enctype. This
path needs no browser, so it is deterministic and fully unit-testable; it exercises
server-side endpoints and validation but not client-side JavaScript (the
:mod:`~modules.forms.driver` handles that).

Authentication (``--cookie``/``--jwt`` via :mod:`modules.authutil`) is honoured, so
forms behind a login are filled as the authenticated user. Submission is gated by
:mod:`~modules.forms.safety`.
"""
from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from urllib.parse import urlsplit

from .models import Form
from .safety import MUTATING_METHODS, is_destructive, masked_fields
from .synth import Synthesizer

try:  # requests is already a project dependency (downloader/fuzzer use it)
    import requests
except ImportError:  # pragma: no cover - exercised only in a stripped env
    requests = None  # type: ignore


@dataclass
class FillPlan:
    """The concrete name→value pairs chosen for one form, plus metadata."""

    action: str
    method: str
    enctype: str
    data: dict[str, str] = dc_field(default_factory=dict)
    source_url: str = ""

    def masked(self) -> dict[str, str]:
        return masked_fields(self.data)


def build_fill_plan(form: Form, synth: Synthesizer) -> FillPlan:
    """Choose a value for every submitable control (required ones always included).

    A browser submits every non-disabled named control that has a value; unchecked
    checkboxes/radios are omitted. We always include ``required`` controls, always
    check a ``required`` checkbox, and include optional controls too so the server
    sees a fully-populated form (maximising the code paths a submission reaches).
    """
    data: dict[str, str] = {}
    seen_radio: set[str] = set()
    for fld in form.submitable_fields():
        if fld.type == "radio":
            if fld.name in seen_radio:      # one value per radio group
                continue
            seen_radio.add(fld.name)
            data[fld.name] = synth.value_for(fld)
            continue
        if fld.type == "checkbox":
            # Check required boxes (e.g. "accept terms"); include others most of the time.
            if fld.required or synth._rng.random() < 0.8:  # noqa: SLF001 - intentional shared RNG
                data[fld.name] = synth.value_for(fld)
            continue
        data[fld.name] = synth.value_for(fld)
    return FillPlan(action=form.resolved_action(), method=form.method or "get",
                    enctype=form.enctype, data=data, source_url=form.source_url)


@dataclass
class SubmitResult:
    action: str
    method: str
    submitted: bool
    reason: str = ""
    status: int | None = None
    response_len: int | None = None
    final_url: str = ""
    fields: dict[str, str] = dc_field(default_factory=dict)
    error: str = ""

    def to_record(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in ("", None, {})}


def submit_form(form: Form, synth: Synthesizer, *, submit: bool = True,
                headers: dict[str, str] | None = None, timeout: float = 15.0,
                extra_denylist: list[str] | None = None, apply_guard: bool = True,
                session=None) -> SubmitResult:
    """Fill ``form`` and (optionally) submit it, honouring the safety guard.

    ``submit=False`` fills and reports the plan without sending anything. When
    ``submit=True``, mutating submissions to destructive/denied endpoints are still
    skipped (with a reason), matching :mod:`~modules.forms.safety` — unless
    ``apply_guard=False`` explicitly disables that protection.
    """
    plan = build_fill_plan(form, synth)
    method = plan.method.upper()
    action = plan.action
    res = SubmitResult(action=action, method=method, submitted=False,
                       fields=plan.masked())

    if not submit:
        res.reason = "fill-only (submit disabled)"
        return res

    if apply_guard:
        danger = (is_destructive(action, extra_denylist)
                  or is_destructive(form.source_url, extra_denylist))
        if danger and method in MUTATING_METHODS:
            res.reason = f"skipped: destructive endpoint ({danger})"
            return res
    if requests is None:
        res.reason = "skipped: requests unavailable"
        return res
    if not action or urlsplit(action).scheme not in ("http", "https"):
        res.reason = f"skipped: non-http action ({action!r})"
        return res

    sess = session or requests.Session()
    try:
        if method == "GET":
            r = sess.get(action, params=plan.data, headers=headers, timeout=timeout,
                         allow_redirects=True)
        else:
            if form.is_multipart:
                # Send as multipart/form-data (files dict with no filename -> plain fields).
                files = {k: (None, v) for k, v in plan.data.items()}
                r = sess.request(method, action, files=files, headers=headers,
                                 timeout=timeout, allow_redirects=True)
            else:
                r = sess.request(method, action, data=plan.data, headers=headers,
                                 timeout=timeout, allow_redirects=True)
        res.submitted = True
        res.status = r.status_code
        res.response_len = len(r.content)
        res.final_url = r.url
    except Exception as ex:  # never abort the batch on one bad form
        res.reason = "submit failed"
        res.error = str(ex)
    return res
