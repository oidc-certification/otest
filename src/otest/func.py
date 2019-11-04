import inspect
import json
import sys

#from urllib.parse import urlencode
#from urllib.parse import urlparse
from future.backports.urllib.parse import urlparse
from future.backports.urllib.parse import urlencode

from otest import ConfigurationError
from otest.check import ERROR
from otest.check import get_id_tokens
from otest.check import State
from otest.events import EV_CONDITION
from otest.events import EV_RESPONSE
from otest.result import get_issuer
from otest.tool import get_redirect_uris

from oic.extension.message import make_software_statement
from oic.utils.keyio import KeyBundle

__author__ = 'roland'


class SetUpError(Exception):
    pass


def set_request_args(oper, args):
    """
    Context:
        Any
    Action:
        Sets a set of request arguments
    Args:
        Request arguments
    Example:

        "set_request_args": {
          "claims": {
            "id_token": {
              "email": {
                "essential": true
              }
            }
          }
        }

        "set_request_args": {
          "scope": [
            "openid",
            "offline_access"
          ],
          "prompt": "consent"
        }

    """
    oper.req_args.update(args)


def set_response_args(oper, args):
    oper.response_args.update(args)


def set_op_args(oper, args):
    """
    Context:
        AccessToken, UserInfo
    Action:
        Sets a set of operational arguments
    Args:
        Operational arguments
    Example:

        "set_op_args": {
          "method": "GET",
          "authn_method": "bearer_header"
        }

        "set_op_args": {
          "request_object_signing_alg": "RS256",
          "request_method": "request"
        }

    """

    oper.op_args.update(args)


def set_arg(oper, args):
    """

    :param oper: Operation instance
    :param args: dictionary with operation parameter as key and parameter
        value as value
    """
    for key, val in args.items():
        setattr(oper, key, val)


def expect_exception(oper, args):
    """
    Context:
        Registration
    Action:
        Verifies that the thrown exception is the one expected.
    Args:
        Expected exception
    Example:
        "expect_exception": "RegistrationError"
    """
    set_arg(oper, {'expect_exception': args})


def conditional_expect(oper, args):
    condition = args["condition"]

    res = True
    for key in list(condition.keys()):
        try:
            assert oper.req_args[key] in condition[key]
        except KeyError:
            pass
        except AssertionError:
            res = False

    for param in ['error', 'exception']:
        do_set = False
        try:
            if res == args["oper"]:
                do_set = True
        except KeyError:
            if res is True:
                do_set = True

        if do_set:
            try:
                setattr(oper, 'expect_{}'.format(param), args[param])
            except KeyError:
                pass


def set_expect_error(oper, args):
    """
    Context:
        Any
    Action:
        Sets a number of expected errors and whether the processing should stop or continue.
    Args:
        error: List of expected error codes
        stop: Whether the processing should stop on receiving an error response.
    Example:
        "set_expect_error": {
          "error": [
            "invalid_grant",
            "access_denied"
          ],
          "stop": false
        }
    """
    set_arg(oper, {'expect_error': args})


def set_allowed_status_codes(oper, args):
    set_arg(oper, {'allowed_status_codes': args})


def set_time_delay(oper, args):
    set_arg(oper, {'delay': args})


def skip_operation(oper, arg):
    if oper.profile[0] in arg["flow_type"]:
        oper.skip = True


def conditional_expect_exception(oper, args):
    """
    Context:
        Registration
    Action:
        Verifies that the thrown exception is the one expected.
    Args:
        Expected exception
    Example:
        "expect_exception": "RegistrationError"
    """
    condition = args["condition"]
    exception = args["exception"]

    res = True
    for key in list(condition.keys()):
        try:
            assert oper.req_args[key] in condition[key]
        except KeyError:
            pass
        except AssertionError:
            res = False

    try:
        if res == args["oper"]:
            oper.expect_exception = exception
    except KeyError:
        if res is True:
            oper.expect_exception = exception


def add_post_condition(oper, args):
    for key, item in args.items():
        oper.tests['post'].append((key, item))


def add_pre_condition(oper, args):
    for key, item in args.items():
        oper.tests['pre'].append((key, item))


def clear_cookies(oper, args):
    oper.client.cookiejar.clear()


def set_uri(oper, args):
    """
    Context:
        Registration
    Action:
        Constructs a URI and assigns it to a request argument
    Args:
        Tuple with request argument and the path to assigned to a base URL, based of the redirect_uri
    Example:

        "set_uri": [
          "tos_uri",
          "static/tos.html"
        ]

    """
    ru = oper.conv.get_redirect_uris()[0]
    p = urlparse(ru)
    oper.req_args[args[0]] = "%s://%s/%s" % (p.scheme, p.netloc, args[1])


def get_base(base_url):
    """
    Make sure a '/' terminated URL is returned
    """
    part = urlparse(base_url)

    if part.path:
        if not part.path.endswith("/"):
            _path = part.path[:] + "/"
        else:
            _path = part.path[:]
    else:
        _path = "/"

    return "%s://%s%s" % (part.scheme, part.netloc, _path,)


def check_endpoint(oper, args):
    try:
        _ = oper.conv.entity.provider_info[args]
    except KeyError:
        oper.conv.events.store(
            EV_CONDITION,
            State("check_endpoint", status=ERROR,
                  message="{} not in provider configuration".format(args)))
        oper.skip = True


def cache_response(oper, arg):
    key = oper.conv.test_id
    oper.cache[key] = oper.conv.events.last_item(EV_RESPONSE)


def restore_response(oper, arg):
    key = oper.conv.test_id
    if oper.conv.events[EV_RESPONSE]:
        _lst = oper.cache[key][:]
        for x in oper.conv.events[EV_RESPONSE]:
            if x not in _lst:
                oper.conv.events.append(_lst)
    else:
        oper.conv.events.extend(oper.cache[key])

    del oper.cache[key]


def rm_claim_from_assertion(oper, arg):
    pass


def set_req_arg_token(oper, arg):
    oper.req_args["token_type_hint"] = arg
    oper.req_args['token'] = getattr(oper._token, arg)


def add_software_statement(oper, arg):
    argkeys = list(arg.keys())
    kwargs = {}

    tre = oper.conf.TRUSTED_REGISTRATION_ENTITY
    iss = tre['iss']
    kb = KeyBundle()
    kb.imp_jwks = json.load(open(tre['jwks']))
    kb.do_keys(kb.imp_jwks['keys'])
    oper.conv.entity.keyjar.add_kb(iss, kb)

    if arg['redirect_uris'] is None:
        kwargs['redirect_uris'] = oper.conv.entity.redirect_uris
    else:
        kwargs['redirect_uris'] = arg['redirect_uris']
    argkeys.remove('redirect_uris')

    if 'jwks_uri' in argkeys:
        if arg['jwks_uri'] is None:
            kwargs['jwks_uri'] = oper.conv.entity.jwks_uri
        else:
            kwargs['jwks_uri'] = arg['jwks_uri']
        argkeys.remove('jwks_uri')
    elif 'jwks' in argkeys:
        if arg['jwks'] is None:
            kwargs['jwks'] = {
                "keys": oper.conv.entity.keyjar.dump_issuer_keys("")}
        else:
            kwargs['jwks'] = arg['jwks']
        argkeys.remove('jwks')

    for a in argkeys:
        kwargs[a] = arg[a]

    oper.req_args['software_statement'] = make_software_statement(
        oper.conv.entity.keyjar, iss=iss, owner=iss, **kwargs)


def set_start_page(oper, args):
    _conf = oper.sh['test_conf']
    _url = _conf['start_page']
    _iss = oper.conv.entity.baseurl
    _params = _conf['params'].replace('<issuer>', _iss)
    _args = dict([p.split('=') for p in _params.split('&')])
    oper.start_page = _url + '?' + urlencode(_args)


def set_target(oper, args):
    oper.op_args['target'] = oper.conv.entity.provider_info['issuer']


def set_info_issuer(oper, args):
    oper.conv.info["issuer"] = oper.conv.get_tool_attribute("issuer")


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj):
            if fname == name:
                return obj

    return None
