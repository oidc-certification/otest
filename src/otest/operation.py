import copy
import inspect
import json
import logging
import time
import sys

import cherrypy
from jwkest import as_bytes
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import Message
from otest import Break, ConfigurationError

from otest.events import EV_EVENT
from otest.events import EV_EXCEPTION
from otest.events import EV_FUNCTION
from otest.events import EV_PROTOCOL_RESPONSE
from otest.events import EV_RESPONSE
from otest.verify import Verify

logger = logging.getLogger(__name__)


def print_result(resp):
    try:
        cl_name = resp.__class__.__name__
    except AttributeError:
        cl_name = ""
        txt = resp
    else:
        txt = json.dumps(resp.to_dict(), sort_keys=True, indent=2,
                         separators=(',', ': '))

    logger.info("{}: {}".format(cl_name, txt))


def request_with_client_http_session(instance, method, url, **kwargs):
    """Use the clients http session to make http request.
    Note: client.http_request function requires the parameters in reverse
    order (compared to the requests library): (method, url) vs (url, method)
    so we can't bind the instance method directly.
    """
    return instance.conv.entity.http_request(url, method)


def link(url):
    return '<a href="{}">link</a>'.format(url)


class Operation(object):
    _tests = {"pre": [], "post": []}
    message_cls = None

    def __init__(self, conv, inut, sh, test_id='', conf=None, funcs=None,
                 check_factory=None, cache=None, profile='', tool_conf=None,
                 **kwargs):
        self.conv = conv
        self.inut = inut
        self.sh = sh
        self.funcs = funcs or {}
        self.test_id = test_id
        self.conf = conf
        self.check_factory = check_factory
        self.cache = cache
        self.profile = profile
        self.tool_conf = tool_conf
        self.req_args = {}
        self.op_args = {}
        self.expect_exception = None
        self.expect_error = None
        self.sequence = []
        self.skip = False
        self.fail = False
        self.allowed_status_codes = [200]
        # detach
        self.tests = copy.deepcopy(self._tests)
        try:
            self.internal = kwargs['internal']
        except KeyError:
            self.internal = True
        self.unsupported = False

    def run(self, *args, **kwargs):
        return None

    def post_tests(self):
        if self.tests["post"]:
            cls_name = self.__class__.__name__
            _ver = Verify(self.check_factory, self.conv, cls_name=cls_name)
            _ver.test_sequence(self.tests["post"])

    def __call__(self, *args, **kwargs):
        if self.skip:
            return
        else:
            cls_name = self.__class__.__name__
            if self.tests["pre"] or self.tests["post"]:
                _ver = Verify(self.check_factory, self.conv, cls_name=cls_name)
            else:
                _ver = None

            if self.tests["pre"]:
                _ver.test_sequence(self.tests["pre"])

            res = self.run(*args, **kwargs)

            if res:
                return res

    def _setup(self):
        if self.skip:  # Don't bother
            return

        for op, arg in list(self.funcs.items()):
            try:
                op(self, arg)
            except ConfigurationError as err:
                _txt = "Configuration error: {}".format(err)
                self.conv.events.store(EV_EXCEPTION, _txt)
                raise cherrypy.HTTPError(message=_txt)
            except Exception as err:
                _txt = "Can't do {}".format(op)
                self.conv.events.store(EV_EXCEPTION, _txt)
                raise cherrypy.HTTPError(message=_txt)

                # self.conv.events.store(EV_OP_ARGS, self.op_args)

    def apply_profile(self, profile_map):
        try:
            kwargs = profile_map[self.__class__][self.profile[0]]
        except KeyError:
            return
        else:
            for op, arg in kwargs.items():
                op(self, arg)

    def op_setup(self):
        pass

    def setup(self, profile_map=None):
        """
        Order between setup methods are significant

        :param profile_map:
        :return:
        """
        if profile_map:
            self.apply_profile(profile_map)
        self.op_setup()
        self._setup()

    def catch_exception_and_error(self, func, **kwargs):
        """
        Seven possible use case
        1) The function returns an instance of the expected class
        2) The function returns a Message instance but not of the expected type
        3) The function returns an expected exception
        4) The function returns an unexpected exception
        5) The function returns an expected error message
        6) The function returns an unexpected error message
        7) Something else is returned.

        :param func:
        :param kwargs:
        :return:
        """
        res = None
        try:
            self.conv.events.store(EV_FUNCTION,
                                   {'name': func.__name__, 'kwargs': kwargs})
            res = func(**kwargs)
        except Exception as err:
            self.conv.events.store(
                EV_EXCEPTION, '{}:{}'.format(err.__class__.__name__, err))
            if not self.expect_exception:
                raise
            elif not err.__class__.__name__ == self.expect_exception:
                raise
            else:
                self.conv.events.store(
                    EV_EVENT,
                    'got expected exception {}'.format(self.expect_exception))
        else:
            if self.expect_exception:
                self.conv.events.store(
                    EV_EVENT, 'Expected exception did not occur')
                raise Exception(
                    "Expected exception '{}'.".format(self.expect_exception))

            if self.expect_error:
                #l = self.conv.events.events[-1].data
                try:
                    assert isinstance(res, ErrorResponse)
                except AssertionError:
                    logger.info(
                        'Expected error not received: {}'.format(res.to_dict()))
                    self.conv.events.store(
                        EV_EVENT, 'Expected error not received')
                else:
                    if res['error'] not in self.expect_error['error']:
                        self.conv.events.store(
                            EV_EVENT,
                            'Expected error not received: got {}'.format(
                                res['error']))
                        logger.info(
                            'Expected error not received: {}'.format(
                                res.to_dict()))
                    else:
                        self.conv.events.store(EV_EVENT, "Got expected error")
                        logger.info(
                            "Got expected error: {}".format(res.to_dict()))
                    try:
                        if self.expect_error['stop']:
                            raise Break('Stop')
                    except KeyError:
                        pass
            else:
                if isinstance(res, ErrorResponse):
                    logger.info(
                        'Unexpected error response: {}'.format(res.to_dict()))
                    self.conv.events.store(EV_EVENT, "Got unexpected error")
                    raise Break('Stop')

            if res:
                if isinstance(res, Message):
                    logger.info('Response: {}'.format(res.to_dict()))

                if isinstance(res, self.message_cls):
                    self.conv.events.store(EV_PROTOCOL_RESPONSE, res)
                elif isinstance(res, ErrorResponse):
                    pass
                elif isinstance(res, Message):
                    self.conv.events.store(EV_EVENT, "Got unexpected response")
                    raise Break('Unexpected response')
                else:
                    self.conv.events.store(EV_RESPONSE, res)
        return res

    def handle_response(self, *args):
        raise NotImplementedError(self.__class__.__name__)

    def handle_request(self, *args, **kwargs):
        raise NotImplementedError(self.__class__.__name__)


class Notice(Operation):
    pre_html = "message.html"

    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.message = ""

    def args(self):
        return {'note': self.message, 'title': self.test_id}

    def __call__(self, *args, **kwargs):
        _msg = self.inut.pre_html[self.pre_html].format(**self.args())
        return as_bytes(_msg)


class Note(Notice):
    pre_html = "note.html"

    def op_setup(self):
        self.message = self.conv.flow["note"]

    def args(self):
        return {
            "next": link("{}continue?path={}&index={}".format(
                self.conv.entity.base_url, self.test_id, self.sh["index"])),
            "back": link(self.conv.entity.base_url),
            "note": self.message,
            "base": link(self.conv.entity.base_url),
            'header': "OpenID Certification OP Test",
            'title': self.test_id
        }


class TimeDelay(Operation):
    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.delay = 30

    def __call__(self, *args, **kwargs):
        time.sleep(self.delay)
        return None


class ProtocolMessage(object):
    def __init__(self, conv, req_args, binding, msg_param=None):
        self.conv = conv
        self.entity = conv.entity
        self.req_args = req_args
        self.binding = binding
        self.msg_param = msg_param or {}
        self.response_args = {}
        self.op_args = {}

    def construct_message(self, *args):
        raise NotImplementedError()

    def handle_response(self, result, *args):
        raise NotImplementedError()


class VerifyConfiguration(Operation):
    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.unsupported = ''

    def __call__(self, *args, **kwargs):
        if self.unsupported:
            raise Break(self.unsupported)


class SessionManagement(Operation):
    pre_html = "session_iframe.html"

    def __call__(self, *args, **kwargs):
        _msg = self.inut.pre_html[self.pre_html]
        # Need to replace client_id, session_state, issuer and
        # session_change_url
        client_id = self.conv.entity.client_id
        _msg = _msg.replace('{client_id}', client_id)
        session_state = ''
        _msg = _msg.replace('{session_state}', session_state)
        issuer = self.conv.entity.provider_info['issuer']
        _msg = _msg.replace('{issuer}', issuer)
        session_change_url = ''
        _msg = _msg.replace('{session_change_url}', session_change_url)
        return as_bytes(_msg)


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj
