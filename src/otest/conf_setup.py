import importlib
import json
import logging
import sys

from mako.lookup import TemplateLookup
from oic.utils.keyio import build_keyjar

from otest.prof_util import ProfileHandler
from otest.rp.setup import read_path2port_map

from otest.flow import FlowState

logger = logging.getLogger(__name__)

RP_ORDER = [
    "rp-discovery", "rp-registration", "rp-response_type",
    "rp-response_mode", "rp-token_endpoint", "rp-id_token",
    "rp-claims_request", "rp-request_uri", "rp-scope", "rp-nonce",
    "rp-key-rotation", "rp-userinfo", "rp-self-issued", "rp-claims"]


OP_ORDER = [
    "Response Type & Response Mode",
    "Response Type",
    "Response Mode",
    "Discovery",
    "Dynamic Client Registration",
    "redirect_uri",
    "ID Token",
    "Client Authentication",
    'Access Token',
    "Userinfo Endpoint",
    'claims Request Parameter',
    "display Request Parameter",
    "nonce Request Parameter",
    "prompt Request Parameter",
    'redirect_uri Request Parameter',
    "request Request Parameter",
    "request_uri Request Parameter",
    "scope Request Parameter",
    "Misc Request Parameters",
    "OAuth behaviors",
    "Key Rotation",
    "End Session",
    "RP Initiated Logout",
    "Back Channel Logout",
    "Front Channel Logout",
    "Session Management"
]


def construct_app_args(args, conf, operations, func, default_profiles,
                       inst_conf, display_order=None):
    """

    :param args: Command arguments, argparse instance
    :param conf: Service configuration
    :param operations: Operations module
    :param func: Functions module
    :param default_profiles: The default profiles module
    :param inst_conf: Test instance configuration
    :return: Application arguments
    """
    sys.path.insert(0, ".")

    # setup_logging("%s/rp_%s.log" % (SERVER_LOG_FOLDER, _port), logger)

    if args.flowdir:
        _flowdir = args.flowdir
    else:
        _flowdir = conf.FLOWDIR

    cls_factories = {'': operations.factory}
    func_factory = func.factory

    try:
        profiles = importlib.import_module(conf.PROFILES)
    except AttributeError:
        profiles = default_profiles

    if display_order is None:
        display_order = OP_ORDER

    flow_state = FlowState(_flowdir, profile_handler=ProfileHandler,
                           cls_factories=cls_factories,
                           func_factory=func_factory,
                           display_order=display_order)

    # Add own keys for signing/encrypting JWTs
    jwks, keyjar, kidd = build_keyjar(conf.KEYS)

    try:
        if args.staticdir:
            _sdir = args.staticdir
        else:
            _sdir = 'jwks'
    except AttributeError:
        _sdir = 'jwks'

    # If this instance is behind a reverse proxy or on its own
    _port = args.port
    if conf.BASE.endswith('/'):
        conf.BASE = conf.BASE[:-1]

    if args.path2port:
        ppmap = read_path2port_map(args.path2port)
        try:
            _path = ppmap[str(_port)]
        except KeyError:
            print('Port not in path2port map file {}'.format(args.path2port))
            sys.exit(-1)

        # if args.xport:
        #     _base = '{}:{}/{}/'.format(conf.BASE, str(_port), _path)
        # else:
        _base = '{}/{}/'.format(conf.BASE, _path)
    else:
        if _port not in [443, 80]:
            _base = '{}:{}'.format(conf.BASE, _port)
        else:
            _base = conf.BASE
        _path = ''

    if not _base.endswith('/'):
        _base += '/'

    # -------- JWKS ---------------

    if args.path2port:
        jwks_uri = "{}{}/jwks_{}.json".format(_base, _sdir, _port)
        f = open('{}/jwks_{}.json'.format(_sdir, _port), "w")
    elif _port not in [443, 80]:
        jwks_uri = "{}:{}/{}/jwks_{}.json".format(conf.BASE, _port, _sdir,
                                                  _port)
        f = open('{}/jwks_{}.json'.format(_sdir, _port), "w")
    else:
        jwks_uri = "{}/{}/jwks.json".format(conf.BASE, _sdir)
        f = open('{}/jwks.json'.format(_sdir), "w")
    f.write(json.dumps(jwks))
    f.close()

    # -------- MAKO setup -----------
    try:
        if args.makodir:
            _dir = args.makodir
            if not _dir.endswith("/"):
                _dir += "/"
        else:
            _dir = "./"
    except AttributeError:
        _dir = './'

    LOOKUP = TemplateLookup(directories=[_dir + 'templates', _dir + 'htdocs'],
                            module_directory=_dir + 'modules',
                            input_encoding='utf-8',
                            output_encoding='utf-8')

    _client_info = inst_conf['client']

    # Now when the basic URL for the RP is constructed update the
    # redirect_uris and the post_logout_redirect_uris
    try:
        ri = _client_info['registration_info']
    except KeyError:
        pass
    else:
        ri['redirect_uris'] = [r.format(_base) for r in ri['redirect_uris']]
        try:
            ri['post_logout_redirect_uris'] = [r.format(_base) for r in
                                               ri['post_logout_redirect_uris']]
        except KeyError:
            pass

    _client_info.update(
        {"base_url": _base, "kid": kidd, "keyjar": keyjar,
         "jwks_uri": jwks_uri}
    )

    # try:
    #     _client_info['client_id'] = _client_info['registration_response'][
    #         'client_id']
    # except KeyError:
    #     pass

    if args.insecure:
        _client_info['verify_ssl'] = False

    # Test profile either as a command line argument or if not that
    # from the configuration file
    # if args.profile:
    #     _profile = args.profile
    # else:
    # _profile = inst_conf['tool']['profile']

    # Application arguments
    app_args = {
        "flow_state": flow_state, "conf": conf, "base_url": _base,
        "client_info": _client_info, "profiles": profiles,
        "operation": operations, "cache": {},  # "profile": _profile,
        "lookup": LOOKUP, 'tool_conf': inst_conf['tool'],
        "profile_handler": ProfileHandler
    }

    return _path, app_args
