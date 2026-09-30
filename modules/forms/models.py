"""Typed representations of a parsed HTML form and its controls."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin


@dataclass
class Field:
    """One form control (``<input>``/``<select>``/``<textarea>``/``<button>``).

    Attribute names mirror the HTML so the synthesizer can honour the same
    validation constraints a browser would enforce (``pattern``, ``min``/``max``,
    ``minlength``/``maxlength``, ``required``, ``<option>`` sets, …).
    """

    tag: str = "input"          # input | select | textarea | button
    type: str = "text"          # the input @type (lowercased); "select"/"textarea"/"button" for those tags
    name: str = ""
    id: str = ""
    value: str = ""             # a pre-filled value / the button's value
    placeholder: str = ""
    pattern: str = ""           # HTML5 validation regex (anchored by the browser)
    autocomplete: str = ""
    required: bool = False
    disabled: bool = False
    readonly: bool = False
    multiple: bool = False      # <select multiple> / <input type=file multiple>
    checked: bool = False       # radio/checkbox initial state
    minlength: int | None = None
    maxlength: int | None = None
    min: str | None = None      # kept as strings: may be a number OR a date/time
    max: str | None = None
    step: str | None = None
    options: list[str] = field(default_factory=list)   # <select>/<datalist> option values
    label: str = ""             # associated <label> text, when found

    @property
    def is_submitable_value(self) -> bool:
        """Whether this control contributes a name=value pair to a submission.

        Disabled controls and nameless controls never submit; a browser also omits
        unchecked checkboxes/radios and file inputs carry no textual value.
        """
        if self.disabled or not self.name:
            return False
        if self.tag == "button" or self.type in ("submit", "reset", "button", "image", "file"):
            return False
        return True

    @property
    def semantic(self) -> str:
        """A best-effort semantic tag inferred from name/id/autocomplete/placeholder.

        Used by the synthesizer to produce human-plausible values (a field called
        ``firstName`` gets a first name, ``zip`` a postal code, …) so server-side
        "looks like a name" checks are satisfied, not just the HTML constraints.
        """
        hay = " ".join((self.name, self.id, self.autocomplete, self.placeholder, self.label)).lower()
        # Order matters: the most specific hints win.
        table = [
            ("email", ("email", "e-mail", "mail")),
            ("firstname", ("firstname", "first-name", "first_name", "given-name", "givenname", "fname")),
            ("lastname", ("lastname", "last-name", "last_name", "family-name", "surname", "lname")),
            ("fullname", ("fullname", "full-name", "your-name", "name")),
            ("username", ("username", "user-name", "user_name", "login", "userid", "handle", "nickname")),
            ("password", ("password", "passwd", "pwd", "pass")),
            ("phone", ("phone", "tel", "mobile", "cell")),
            ("url", ("url", "website", "homepage", "link")),
            ("zip", ("zip", "postal", "postcode")),
            ("city", ("city", "town")),
            ("state", ("state", "province", "region")),
            ("country", ("country",)),
            ("street", ("street", "address", "addr", "addressline")),
            ("company", ("company", "organization", "organisation", "org")),
            ("card", ("cardnumber", "card-number", "cardno", "ccnum", "creditcard", "cc-number", "pan")),
            ("cvv", ("cvv", "cvc", "csc", "securitycode")),
            ("expiry", ("expiry", "exp-date", "expdate", "cc-exp")),
            ("otp", ("otp", "onetimecode", "one-time", "2fa", "mfa", "verificationcode", "code")),
            ("date", ("dob", "birth", "date")),
            ("age", ("age",)),
            ("quantity", ("quantity", "qty", "amount", "count")),
            ("search", ("search", "query", "keyword", "q")),
            ("subject", ("subject", "title")),
            ("message", ("message", "comment", "body", "content", "feedback", "review", "description", "bio")),
        ]
        for tag, needles in table:
            if any(n in hay for n in needles):
                return tag
        return ""


@dataclass
class Form:
    """A parsed ``<form>`` (or a synthetic form for controls outside any form)."""

    action: str = ""            # resolved absolute URL to submit to
    method: str = "get"         # get | post (lowercased)
    enctype: str = "application/x-www-form-urlencoded"
    name: str = ""
    id: str = ""
    fields: list[Field] = field(default_factory=list)
    source_url: str = ""        # the page the form was found on

    def resolved_action(self) -> str:
        """The absolute submission URL (``action`` resolved against the page)."""
        if not self.action:
            return self.source_url
        return urljoin(self.source_url, self.action)

    @property
    def is_multipart(self) -> bool:
        return "multipart" in (self.enctype or "").lower()

    def submitable_fields(self) -> list[Field]:
        return [f for f in self.fields if f.is_submitable_value]
