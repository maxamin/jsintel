"""Parse HTML into :class:`Form` / :class:`Field` objects with the stdlib.

No third-party HTML library is used (the project keeps its runtime dependencies
minimal). ``html.parser`` is a permissive SAX-style parser, which is exactly what
we want for real-world, frequently-malformed markup: unknown/unclosed tags are
tolerated rather than fatal.

Controls that a browser associates with a form via the ``form="<id>"`` attribute
even though they sit *outside* the ``<form>`` element are attached to that form.
Controls with no owning form at all are collected into a synthetic trailing form
whose action defaults to the page URL, so a JS-driven ``<input>+<button>`` pair
with no ``<form>`` wrapper is still discovered and exercised.
"""
from __future__ import annotations

from html.parser import HTMLParser

from .models import Field, Form

_INT_ATTRS = {"minlength", "maxlength"}


def _to_int(v: str | None) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


class _FormHTMLParser(HTMLParser):
    """Collect forms, their controls, controls linked by ``form=`` and orphan controls."""

    def __init__(self, source_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.source_url = source_url
        self.forms: list[Form] = []
        self._form_by_id: dict[str, Form] = {}
        self._stack: list[Form] = []            # currently-open <form> elements
        self._detached: list[tuple[str, Field]] = []  # (form_id, field) for form="..." controls
        self._orphans: list[Field] = []         # controls with no owning form
        # <select>/<textarea>/<label> capture state
        self._cur_select: Field | None = None
        self._cur_select_form: Form | None = None
        self._pending_option: str | None = None
        self._in_textarea = False
        self._in_label = False
        self._label_for = ""
        self._label_buf: list[str] = []
        self._labels_by_for: dict[str, str] = {}
        # <option> capture: a value attr that is absent (None) differs from one that is
        # explicitly empty (""), and the visible text is only used when no value attr.
        self._opt_open = False
        self._opt_value: str | None = None
        self._opt_text: list[str] = []
        self._opt_selected = False

    # -- helpers ---------------------------------------------------------------
    def _attach(self, attrs: dict[str, str], fld: Field) -> None:
        """Attach a control to its owning form (explicit form=, open form, or orphan)."""
        form_id = attrs.get("form")
        if form_id:
            self._detached.append((form_id, fld))
        elif self._stack:
            self._stack[-1].fields.append(fld)
        else:
            self._orphans.append(fld)

    def _field_from_input(self, attrs: dict[str, str]) -> Field:
        return Field(
            tag="input",
            type=(attrs.get("type") or "text").strip().lower(),
            name=attrs.get("name", ""),
            id=attrs.get("id", ""),
            value=attrs.get("value", ""),
            placeholder=attrs.get("placeholder", ""),
            pattern=attrs.get("pattern", ""),
            autocomplete=attrs.get("autocomplete", ""),
            required="required" in attrs,
            disabled="disabled" in attrs,
            readonly="readonly" in attrs,
            multiple="multiple" in attrs,
            checked="checked" in attrs,
            minlength=_to_int(attrs.get("minlength")),
            maxlength=_to_int(attrs.get("maxlength")),
            min=attrs.get("min"),
            max=attrs.get("max"),
            step=attrs.get("step"),
        )

    def _flush_option(self) -> None:
        """Commit the currently-open <option> to its select's option list."""
        if not self._opt_open or self._cur_select is None:
            self._opt_open = False
            return
        text = "".join(self._opt_text).strip()
        value = self._opt_value if self._opt_value is not None else text
        self._cur_select.options.append(value)
        if self._opt_selected:
            self._cur_select.value = value
        self._opt_open = False
        self._opt_value = None
        self._opt_text = []
        self._opt_selected = False

    # -- HTMLParser hooks ------------------------------------------------------
    def handle_starttag(self, tag: str, attrs_list):  # noqa: ANN001
        attrs = {k.lower(): (v if v is not None else "") for k, v in attrs_list}
        if tag == "form":
            form = Form(
                action=attrs.get("action", ""),
                method=(attrs.get("method") or "get").strip().lower() or "get",
                enctype=(attrs.get("enctype") or "application/x-www-form-urlencoded").strip().lower(),
                name=attrs.get("name", ""),
                id=attrs.get("id", ""),
                source_url=self.source_url,
            )
            self.forms.append(form)
            self._stack.append(form)
            if form.id:
                self._form_by_id[form.id] = form
            return
        if tag == "input":
            self._attach(attrs, self._field_from_input(attrs))
            return
        if tag == "textarea":
            fld = Field(tag="textarea", type="textarea", name=attrs.get("name", ""),
                        id=attrs.get("id", ""), placeholder=attrs.get("placeholder", ""),
                        required="required" in attrs, disabled="disabled" in attrs,
                        readonly="readonly" in attrs,
                        minlength=_to_int(attrs.get("minlength")),
                        maxlength=_to_int(attrs.get("maxlength")))
            self._attach(attrs, fld)
            self._in_textarea = True
            return
        if tag == "select":
            fld = Field(tag="select", type="select", name=attrs.get("name", ""),
                        id=attrs.get("id", ""), required="required" in attrs,
                        disabled="disabled" in attrs, multiple="multiple" in attrs)
            self._cur_select = fld
            self._cur_select_form = self._stack[-1] if self._stack else None
            # Remember explicit form= linkage / orphan status for when </select> closes.
            self._cur_select._form_link = attrs.get("form", "")  # type: ignore[attr-defined]
            return
        if tag == "option" and self._cur_select is not None:
            self._flush_option()
            self._opt_open = True
            self._opt_value = attrs.get("value")  # None when the attr is absent
            self._opt_text = []
            self._opt_selected = "selected" in attrs
            return
        if tag == "button":
            self._attach(attrs, Field(tag="button", type=(attrs.get("type") or "submit").strip().lower(),
                                      name=attrs.get("name", ""), id=attrs.get("id", ""),
                                      value=attrs.get("value", ""), disabled="disabled" in attrs))
            return
        if tag == "label":
            self._in_label = True
            self._label_for = attrs.get("for", "")
            self._label_buf = []

    def handle_startendtag(self, tag: str, attrs_list):  # <input/> self-closing
        self.handle_starttag(tag, attrs_list)
        if tag in ("textarea",):
            self._in_textarea = False

    def handle_endtag(self, tag: str):
        if tag == "form" and self._stack:
            self._stack.pop()
        elif tag == "textarea":
            self._in_textarea = False
        elif tag == "option":
            self._flush_option()
        elif tag == "select" and self._cur_select is not None:
            self._flush_option()
            sel = self._cur_select
            link = getattr(sel, "_form_link", "")
            if link:
                self._detached.append((link, sel))
            elif self._cur_select_form is not None:
                self._cur_select_form.fields.append(sel)
            else:
                self._orphans.append(sel)
            self._cur_select = None
            self._cur_select_form = None
        elif tag == "label" and self._in_label:
            self._in_label = False
            text = " ".join("".join(self._label_buf).split())
            # A <label> may appear before OR after the control it references, so record
            # the text by @for id and attach it in result() once all fields are known.
            if self._label_for and text:
                self._labels_by_for.setdefault(self._label_for, text)

    def handle_data(self, data: str):
        if self._opt_open:
            self._opt_text.append(data)
        if self._in_label:
            self._label_buf.append(data)

    # -- finalize --------------------------------------------------------------
    def result(self) -> list[Form]:
        # Attach form="<id>"-linked controls to their forms (or to a synthetic form).
        if self._detached:
            synthetic: Form | None = None
            for form_id, fld in self._detached:
                target = self._form_by_id.get(form_id)
                if target is None:
                    if synthetic is None:
                        synthetic = Form(action="", method="get", source_url=self.source_url,
                                         name="__detached__")
                        self.forms.append(synthetic)
                    target = synthetic
                target.fields.append(fld)
        # Orphan controls (no <form>, no form=) -> one synthetic form for the page.
        if self._orphans:
            self.forms.append(Form(action="", method="get", source_url=self.source_url,
                                   name="__orphans__", fields=list(self._orphans)))
        # Attach <label for=id> text to controls now that every field exists.
        if self._labels_by_for:
            for form in self.forms:
                for f in form.fields:
                    if f.id and not f.label and f.id in self._labels_by_for:
                        f.label = self._labels_by_for[f.id]
        return self.forms


def parse_forms(html: str, source_url: str = "") -> list[Form]:
    """Parse ``html`` (from ``source_url``) into a list of :class:`Form`.

    Never raises on malformed markup; returns an empty list when there is nothing
    form-like to work with.
    """
    if not html:
        return []
    p = _FormHTMLParser(source_url)
    try:
        p.feed(html)
        p.close()
    except Exception:
        # html.parser is permissive, but guard anyway: a partial parse is still useful.
        pass
    return p.result()
