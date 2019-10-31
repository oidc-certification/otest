import logging

import cherrypy
from future.backports.urllib.parse import quote_plus
from oic.utils.http_util import Redirect
from oic.utils.http_util import Response

from otest import Break
from otest import ConditionError
from otest import Done
from otest import exception_trace
from otest import tool
from otest.check import CRITICAL
from otest.check import ERROR
from otest.check import OK
from otest.check import State
from otest.events import EV_CONDITION
from otest.events import EV_OPERATION
from otest.events import EV_REDIRECT_URL
from otest.prof_util import compress_profile
from otest.prof_util import from_profile
from otest.prof_util import to_profile
from otest.result import Result
from otest.result import safe_path
from otest.verify import Verify

# from urllib.parse import parse_qs

__author__ = 'roland'

logger = logging.getLogger(__name__)


class OutOfSync(Exception):
    pass


class Tester(tool.Tester):
    def __init__(self, io, sh, profiles, flows=None,
                 check_factory=None, msg_factory=None, cache=None,
                 map_prof=None, **kwargs):
        tool.Tester.__init__(self, io, sh, flows=flows,
                             msg_factory=msg_factory, cache=cache,
                             check_factory=check_factory, **kwargs)
        self.profiles = profiles
        self.map_prof = map_prof
        self.conv = None

    def match_profile(self, test_id):
        _spec = self.flows[test_id]
        return self.map_prof(self.sh.profile.split("."),
                             _spec["profile"].split("."))

    def fname(self, test_id):
        try:
            return safe_path(
                self.conv.entity.provider_info['issuer'],
                self.sh.profile, test_id)
        except KeyError:
            return safe_path('dummy', self.sh.profile, test_id)

    def run_flow(self, test_id, index=0, profiles=None, conf=None):
        logger.info("<=<=<=<=< %s >=>=>=>=>" % test_id)
        self.flows.complete[test_id] = False
        self.conv.test_id = test_id
        self.conv.conf = conf

        if index >= len(self.conv.sequence):
            return CRITICAL

        res = Result(self.sh, self.kwargs['profile_handler'])

        _oper = None
        for item in self.conv.sequence[index:]:
            self.sh["index"] = index
            if isinstance(item, tuple):
                cls, funcs = item
            else:
                cls = item
                funcs = {}

            _name = cls.__name__
            _line = "<--<-- {} --- {} -->-->".format(index, _name)
            logger.info(_line)
            self.conv.events.store(EV_OPERATION, _line)
            try:
                _oper = cls(conv=self.conv, inut=self.inut, sh=self.sh,
                            profile=self.sh.profile, test_id=test_id, conf=conf,
                            funcs=funcs, check_factory=self.check_factory,
                            cache=self.cache,
                            tool_conf=self.kwargs['tool_conf'])
                self.conv.operation = _oper
                _oper.setup(self.profiles.PROFILEMAP)
                if _oper.fail:
                    break
                resp = _oper()
            except Break:
                break
            except cherrypy.HTTPError:
                raise
            except Exception as err:
                self.conv.events.store(
                    EV_CONDITION,
                    State(test_id=test_id, status=ERROR, message=err,
                          context=cls.__name__))
                _trace = exception_trace(cls.__name__, err, logger)
                self.sh["index"] = index
                self.store_result(res)
                return {'exception_trace': _trace}
            else:
                rsp = self.handle_response(resp, index)
                if rsp:
                    self.store_result(res)
                    return self.inut.respond(rsp)

            index += 1
            if index == len(self.conv.sequence):
                break

        if isinstance(_oper, Done):
            try:
                if self.conv.flow["assert"]:
                    _ver = Verify(self.check_factory, self.conv)
                    _ver.test_sequence(self.conv.flow["assert"])
            except (KeyError, Break):
                self.conv.events.store(EV_CONDITION, State('Done', status=OK))
            except ConditionError:
                pass
            except Exception as err:
                raise
            else:
                self.conv.events.store(EV_CONDITION, State('Done', status=OK))

        tinfo = self.store_result(res)
        return tinfo['state']


class ClTester(Tester):
    pass


class WebTester(Tester):
    def display_test_list(self):
        try:
            if self.sh.session_init():
                return self.inut.flow_list()
            else:
                try:
                    resp = Redirect("%sopresult#%s" % (
                        self.kwargs['base_url'], self.sh["testid"][0]))
                except KeyError:
                    return self.inut.flow_list()
                else:
                    return resp(self.inut.environ, self.inut.start_response)
        except Exception as err:
            exception_trace("display_test_list", err)
            return self.inut.err_response("session_setup", err)

    def set_profile(self, info):
        try:
            old = from_profile(self.sh.profile)

            new = from_profile(to_profile(info))
            for attr in ['enc', 'extra', 'none', 'return_type', 'sig', 'form_post',
                         "front", "back", "session", "rp_init"]:
                old[attr] = new[attr]

            # Store new configuration
            try:
                rest = self.sh.extra['rest']
            except KeyError:
                self.conv.tool_conf.update(compress_profile(old))
            else:
                qp = [quote_plus(p) for p in [self.sh.iss, self.sh.tag]]
                _, _conf = rest.read_conf(*qp)
                _conf['tool'].update(compress_profile(old))
                rest.store(qp[0], qp[1], _conf)

                # This will fail if no test has been run before the conf
                # is changed
                try:
                    self.conv.tool_conf = _conf['tool']
                except AttributeError:
                    pass

            # reset all test flows
            self.flows.test_info = {}
            self.flows.complete = {}
            self.sh.reset_session(profile=old['profile'])
            # Back to test list
            return self.inut.flow_list()
        except Exception as err:
            return self.inut.err_response("profile", err)

    def handle_response(self, resp, index, oper=None):
        if resp:
            self.sh["index"] = index
            if isinstance(resp, Response):
                if self.conv.events.last_event_type() != EV_REDIRECT_URL:
                    self.conv.events.store(EV_REDIRECT_URL, resp.message)
                return resp(self.inut.environ, self.inut.start_response)
            else:
                return resp
        else:
            return None

    def cont(self, **kwargs):
        path = kwargs['path']
        index = int(kwargs['index'])
        index += 1

        self.store_result()

        try:
            return self.run_flow(path, index=index)
        except cherrypy.HTTPRedirect:
            raise
        except Exception as err:
            exception_trace("", err, logger)
            self.store_result()
            return self.inut.err_response("run", err)

    def async_response(self, conf, response=None):
        index = self.sh["index"]
        item = self.sh["sequence"][index]
        self.conv = self.sh["conv"]

        if isinstance(item, tuple):
            cls, funcs = item
        else:
            cls = item

        logger.info("<--<-- {} --- {}".format(index, cls.__name__))
        resp = self.conv.operation.parse_response(self.sh["testid"],
                                                  self.inut,
                                                  self.message_factory,
                                                  response=response)
        if resp:
            return resp

        index += 1

        return self.run_flow(self.sh["testid"], index=index)

    def handle_request(self, request=None, request_args=None, **kwargs):
        index = self.sh["index"]
        try:
            item = self.sh["sequence"][index]
        except IndexError:  # things have gotten slightly out of hand
            return True

        self.conv = self.sh["conv"]

        if isinstance(item, tuple):
            cls, funcs = item
        else:
            cls = item
            funcs = {}

        if isinstance(item, Done):  # I'm completely out of wack
            raise OutOfSync()

        _line = "<--<-- {} --- {} -->-->".format(index, cls.__name__)
        logger.info(_line)
        self.conv.events.store(EV_OPERATION, _line)
        _oper = cls(conv=self.conv, inut=self.inut, sh=self.sh,
                    profile=self.sh.profile, test_id=self.sh["testid"],
                    conf=self.conv.conf, funcs=funcs,
                    check_factory=self.check_factory, cache=self.cache,
                    tool_conf=self.kwargs['tool_conf'])
        self.conv.operation = _oper
        resp = self.conv.operation.handle_request(self.message_factory,
                                                  request=request,
                                                  request_args=request_args)

        if resp:
            return resp

        index += 1
        return self.run_flow(self.sh["testid"], index=index)
