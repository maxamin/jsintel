"""Active form discovery, in-norm data synthesis, and JS/XHR triggering.

This package is JSIntel's analogue of OWASP ZAP's *AJAX Spider* + *Form Handler*
add-on (OWTF has a comparable active crawler): it finds HTML forms, fills every
field with realistic, spec-valid random data so client- and server-side
validation does not reject it, and then drives the page so its JavaScript event
handlers and XHR/fetch/WebSocket calls fire — surfacing endpoints a passive crawl
never sees.

Two submission engines share one synthesis brain:

* ``engine`` — a dependency-light, ``requests``-based submitter that POSTs/GETs the
  synthesized values straight to a form's ``action``. Fully deterministic and
  unit-testable; it exercises server endpoints but not client-side JS.
* ``driver`` — a best-effort headless-Chromium (CDP) driver that loads the page,
  instruments ``XMLHttpRequest``/``fetch``/``WebSocket``, applies the synthesized
  values, dispatches input/change/submit/click events, and reads back the requests
  the app's own JavaScript made. Gated on Chromium being present.

Safety: like the fuzzer and screenshotter this stage sends live requests and is
therefore scope- and authorization-gated by the caller. Submission is on by
default, but a built-in, overridable deny-list skips obviously destructive or
session-ending targets (payment/checkout/swap/DeFi/withdraw/delete/logout).
"""
from __future__ import annotations
