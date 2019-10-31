from otest.prof_util import SEMAP

from otest.prof_util import SESSION

from otest.aus.preproc import PMAP
from otest.prof_util import CRYPTO
from otest.prof_util import EMAP
from otest.prof_util import EXTRAS
from otest.prof_util import FORMPOST

PMAPL = list(PMAP.keys())
PMAPL.sort()

L2I = {"discovery": 1, "registration": 2}
LONG_NAMES = {"none": "none", "sig": "signing", "enc": "encryption",
              "front": "frontchannel logout", "back": "backchannel logout",
              "session": 'session management', "rp_init": "RP initiated logout"}

RADIO = '<div class="radio"><label><input type="radio" name="{}" value="{}">{}</label></div>'
RADIO_C = '<div class="radio"><label><input type="radio" name="{}" value="{}" checked>{}</label></div>'
CHECK = '<div class="checkbox"><label><input type="checkbox" name="{}">{}</label></div>'
CHECK_C = '<div class="checkbox"><label><input type="checkbox" name="{}" checked>{}</label></div>'


def profile_form(prof):
    p = prof.split(".")
    el = []
    for key in PMAPL:
        txt = PMAP[key]
        if key == p[0]:
            el.append(RADIO_C.format('return_type', key, txt))
        else:
            el.append(RADIO.format('return_type', key, txt))
    el.append("<br>")
    el.append("These you can't change here:")
    el.append("<ul>")
    for mode in ["discovery", "registration"]:
        if p[L2I[mode]] == "T":
            el.append("<li>Dynamic %s" % mode)
        else:
            el.append("<li>Static %s" % mode)

    el.append(
        "</ul><p>Response mode form_post support:</br>")
    el.append(
        "<i>(make sure to register https://&lt;host&gt;:&lt;port&gt;/authz_post as (one of) the redirect URI(s) when enabled!)</i></li></br>")
    if len(p) > FORMPOST and p[FORMPOST] == "T":
        el.append(CHECK_C.format('form_post', ''))
    else:
        el.append(CHECK.format('form_post', ''))
    el.append('</p>')

    el.append("</ul><p>Cryptographic support:<br>")
    if len(p) > CRYPTO:
        vs = p[CRYPTO]
    else:
        vs = ''

    for code, attr in EMAP.items():
        if code in vs:
            el.append(CHECK_C.format(attr, LONG_NAMES[attr]))
        else:
            el.append(CHECK.format(attr, LONG_NAMES[attr]))
    el.append("</p>")

    el.append("</ul><p>Session management and logout support:<br>")
    if len(p) > SESSION:
        vs = p[SESSION]
    else:
        vs = ''

    for code, attr in SEMAP.items():
        if code in vs:
            el.append(CHECK_C.format(attr, LONG_NAMES[attr]))
        else:
            el.append(CHECK.format(attr, LONG_NAMES[attr]))
    el.append("</p>")

    el.append(
        '</ul><p>Check this if you want extra tests (not needed for any '
        'certification profiles): ')
    if len(p) > EXTRAS and p[EXTRAS] == "+":
        el.append(CHECK_C.format('extra', ''))
    else:
        el.append(CHECK.format('extra', ''))
    el.append('</p>')
    return "\n".join(el)
