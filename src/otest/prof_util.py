import os

from future.backports.urllib.parse import quote_plus

from otest.time_util import in_a_while
from otest.utils import with_or_without_slash

RESPONSE = 0
WEBFINGER = 1
DISCOVER = 2
REGISTER = 3
CRYPTO = 4
EXTRAS = 5
FORMPOST = 6
SESSION = 7

LABEL = ['return_type', 'webfinger', 'discover', 'register', 'crypto',
         'extra', "form_post", "logout"]

__author__ = 'roland'

EMAP = {'s': 'sig', 'n': 'none', 'e': 'enc'}
EKEYS = list(EMAP.keys())
EKEYS.sort()  # Make the result deterministic

SEMAP = {'f': "front", "b": "back", "s": "session", "r": "rp_init"}
SKEYS = list(SEMAP.keys())
SKEYS.sort()

PKEYS = LABEL[:]
PKEYS.remove('crypto')
PKEYS.extend(list(EMAP.values()))
PKEYS.remove('logout')
PKEYS.extend(list(SEMAP.values()))

RT = {"C": "code", "I": "id_token", "T": "token", "CT": "code token",
      'CI': 'code id_token', 'IT': 'id_token token',
      'CIT': 'code id_token token'}
RT_INV = dict([(v, k) for k, v in RT.items()])

WF = {'T': 'webfinger', 'F': 'no-webfinger'}
OC = {"T": "discovery", "F": "no-discovery"}
REG = {"T": "dynamic", "F": "static"}
CR = {"n": "none", "s": "sign", "e": "encrypt"}
EX = {"+": "extras"}
FP = {'T': 'form_post'}
SE = {'f': "frontchannel-logout", "b": "backchannel-logout", "s": "session_management",
      "r": "rp-initiated-logout"}

ATTR = ["return_type", "webfinger", "openid-configuration", "registration",
        "crypto", "extras", "form_post", "logout"]


def simplify_return_type(spec):
    if ',' in spec:
        p = spec.split(',')
    elif ' ' in spec:
        p = spec.split(' ')
    else:
        p = [spec]
    p.sort()
    return RT_INV[' '.join(p)]


def abbr_return_type(spec):
    return RT[spec]


def verify_profile(profile):
    p = profile.split('.')
    if len(p) < 4:
        return False
    if p[0] not in ['C', 'I', 'IT', 'CT', 'CIT', 'CI']:
        return False
    for i in range(1, 4):
        if p[i] not in ['F', 'T']:
            return False
    return True


def from_profile(code):
    # Of the form <typ>.<webf>.<disc>.<reg>.*['+'/'n'/'s'/'se']
    # for example:
    # C.T.T.T..  - code response_type, webfinger & dynamic discovery &
    #                                   registration
    # CIT.F.T.F.. - response_type=["code","id_token","token"],
    #               No webfinger support,
    #               does dynamic discovery
    #               and static client registration

    p = code.split('.')

    _prof = {"return_type": p[RESPONSE],
             "extra": False,
             "sig": True,
             'enc': False,
             'none': False,
             'form_post': False,
             "front": False,
             "back": False,
             "session": False,
             "rp_init": False}

    for x, y in {WEBFINGER: 'webfinger', DISCOVER: 'discover',
                 REGISTER: 'register'}.items():
        try:
            _prof[y] = (p[x] == 'T')
        except (KeyError, IndexError):
            _prof[y] = True

    if len(p) > CRYPTO:
        for k, v in EMAP.items():
            if k in p[CRYPTO]:
                _prof[v] = True

        if len(p) > EXTRAS:
            if '+' in p[EXTRAS]:
                _prof['extra'] = True

            if len(p) > FORMPOST:
                if 'T' in p[FORMPOST]:
                    _prof['form_post'] = True

                if len(p) > SESSION:
                    if len(p[SESSION]) and 'r' not in p[SESSION]:
                        _prof[SEMAP['r']] = True

                    for k, v in SEMAP.items():
                        if k in p[SESSION]:
                            _prof[v] = True

    return _prof


def to_profile(pdict):
    code = [pdict["return_type"]]

    for key in ["webfinger", "discover", "register"]:
        try:
            if pdict[key]:
                code.append("T")
            else:
                code.append("F")
        except KeyError:
            code.append("F")

    # Do the rest backwards
    tail = []
    for typ, val in [('form_post', 'T'), ('extra', '+')]:
        try:
            _fp = pdict[typ]
        except KeyError:
            tail.append('')
        else:
            if _fp:
                tail.append(val)
            else:
                tail.append('')

    ext = ''
    for k in EKEYS:
        try:
            if pdict[EMAP[k]]:
                ext += k
        except KeyError:
            pass

    if ext:
        tail.append(ext)
    else:
        tail.append('')

    i = 0
    while tail[i] == '':
        i += 1
        if i == len(tail):
            break

    if i == len(tail):
        pass
    else:
        tail = tail[i:]
        tail.reverse()
        code.extend(tail)

    return ".".join(code)


def repr_profile(profile, representation="list", with_webfinger=True):
    """

    :param profile: Expected to be list of items
    :param representation: Which type of output that is expected
    :param with_webfinger: Is WebFinger specification included
    :return:
    """
    prof = ["+".join([RT[x] for x in profile[0]])]
    if with_webfinger:
        _spec = [WF, OC, REG]
    else:
        _spec = [OC, REG]

    i = 0
    for tag_text in _spec:
        i += 1
        try:
            prof.append("%s" % tag_text[profile[i]])
        except IndexError:
            pass

    try:
        i += 1
        _val = "%s" % "+".join([CR[x] for x in profile[i]])
    except (KeyError, IndexError):
        pass
    else:
        if _val:
            prof.append(_val)
        i += 1
        try:
            _val = profile[i]
        except (KeyError, IndexError):
            pass
        else:
            if _val:
                prof.append("%s" % EX[_val])
            i += 1
            try:
                _val = profile[i]
            except (KeyError, IndexError):
                pass
            else:
                if _val:
                    prof.append("%s" % FP[_val])

    if representation == "list":
        return prof
    elif representation == "dict":
        ret = {}
        for r in range(0, len(prof)):
            ret[ATTR[r]] = prof[r]

        if "extras" in ret:
            ret["extras"] = True
        return ret


def do_registration(profile):
    if profile.split('.')[REGISTER] == 'F':
        return False
    else:
        return True


def do_discovery(profile):
    if profile.split('.')[DISCOVER] == 'F':
        return False
    else:
        return True


def return_type(profile):
    return profile.split('.')[RESPONSE]


def update_profile(old, new):
    oa = from_profile(old)
    na = from_profile(new)
    oa.update(na)
    return to_profile(oa)


def compress_profile(item):
    _prof = to_profile(item)
    item['profile'] = _prof
    for attr in PKEYS:
        try:
            del item[attr]
        except KeyError:
            pass
    return item


def expand_profile(item):
    try:
        _prof = from_profile(item['profile'])
    except KeyError:
        pass
    else:
        del item['profile']
        item.update(_prof)

    return item


def _cmp_prof(a, b):
    """

    :param a: list of strings
    :param b: list of strings
    :return: True/False if a maps to b
    """
    # basic, implicit, hybrid
    if b[RESPONSE] != "":
        if a[RESPONSE] not in b[RESPONSE].split(','):
            return False

    try:
        # dynamic discovery & registry
        for n in [WEBFINGER, DISCOVER, REGISTER]:
            if b[n] != "":
                if a[n] != b[n]:
                    return False
    except IndexError:
        print("Too short a:{}, b:{}".format(a, b))
        raise

    if len(a) > CRYPTO:
        if len(b) > CRYPTO:
            if b[CRYPTO] != '':
                if not set(a[CRYPTO]).issuperset(set(b[CRYPTO])):
                    return False

    for var in [EXTRAS, FORMPOST]:
        if len(b) > var:
            if len(a) > var:
                if a[var] != b[var]:
                    return False
            else:
                return False

    return True


def map_prof(a, b):
    """
    Checks that the demands in b are met by a

    :param a:
    :param b:
    :return: True/False
    """
    if a == b:
        return True

    if isinstance(b, list):
        return _cmp_prof(a, b)
    elif '.' in b:
        b = b.split('.')
        if '.' in a:
            a = a.split('.')
        return _cmp_prof(a, b)
    else:
        if b == '*':
            return True
        else:
            bl = b.split(',')
            if isinstance(a, list):
                if a[0] in bl:
                    return True
                else:
                    return False
            elif a in bl:
                return True
            else:
                return False


class ProfileHandler(object):
    def __init__(self, session):
        self.session = session

    @staticmethod
    def webfinger(profile):
        return profile[WEBFINGER] == "T"

    @staticmethod
    def discover(profile):
        return profile[DISCOVER] == "T"

    @staticmethod
    def register(profile):
        return profile[REGISTER] == "T"

    @staticmethod
    def form_post(profile):
        return profile[FORMPOST] == "T"

    def to_profile(self, representation="list"):
        return []

    def get_profile_info(self, test_id=None):
        try:
            _conv = self.session["conv"]
        except KeyError:
            pass
        else:
            try:
                iss = _conv.entity.provider_info["issuer"]
            except (TypeError, KeyError):
                iss = ""

            profile = self.to_profile("dict")

            if test_id is None:
                try:
                    test_id = self.session["testid"]
                except KeyError:
                    return {}

            return {
                "Issuer": iss, "Profile": profile,
                "Test ID": test_id,
                "Test description": self.session.test_flows[test_id]["desc"],
                "Timestamp": in_a_while()}

        return {}

    def log_path(self, **kwargs):
        _conv = self.session["conv"]

        try:
            iss = _conv.entity.provider_info["issuer"]
        except (TypeError, KeyError):
            return ""
        else:
            qiss = quote_plus(iss)

        path = with_or_without_slash(os.path.join("log", qiss))
        if path is None:
            path = os.path.join("log", qiss)

        prof = ".".join(self.to_profile())

        if not os.path.isdir("{}/{}".format(path, prof)):
            os.makedirs("{}/{}".format(path, prof))

        if 'test_id' not in kwargs:
            _test_id = self.session["testid"]
        else:
            _test_id = kwargs['test_id']

        return "{}/{}/{}".format(path, prof, _test_id)


class SimpleProfileHandler(ProfileHandler):
    @staticmethod
    def webfinger(profile):
        return True

    @staticmethod
    def discover(profile):
        return True

    @staticmethod
    def register(profile):
        return True

    @staticmethod
    def form_post(profile):
        return True

    def get_profile_info(self, test_id=None):
        try:
            _conv = self.session["conv"]
        except KeyError:
            pass
        else:
            try:
                iss = _conv.entity.provider_info["issuer"]
            except AttributeError:
                iss = _conv.entity.baseurl
            except (TypeError, KeyError):
                iss = ""

            profile = RT[''.join(self.session["profile"])]

            if test_id is None:
                try:
                    test_id = self.session["testid"]
                except KeyError:
                    return {}

            return {
                "Issuer": iss, "Profile": profile,
                "Test ID": test_id,
                "Test description": self.session.test_flows[test_id]["desc"],
                "Timestamp": in_a_while()}
        return {}

    def log_path(self, **kwargs):
        path = os.path.join("log", kwargs['sid'])

        prof = ".".join(self.to_profile())

        if not os.path.isdir("{}/{}".format(path, prof)):
            os.makedirs("{}/{}".format(path, prof))

        try:
            _test_id = kwargs['test_id']
        except KeyError:
            _test_id = self.session["testid"]

        return "{}/{}/{}".format(path, prof, _test_id)
