import copy
import inspect
import logging
import sys

from bs4 import BeautifulSoup
from oic.exception import IssuerMismatch
from oic.oauth2 import ResponseError
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import Message
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import VerificationError
from oic.oauth2.util import URL_ENCODED
from oic.oic.message import IdToken
from oic.utils.http_util import Redirect
from requests.models import Response

from otest import Break
from otest import Unknown
from otest import operation
from otest.check import ERROR
from otest.check import State
from otest.events import EV_FAULT
from otest.events import EV_HTTP_RESPONSE
from otest.events import EV_JWE_HEADER
from otest.events import EV_JWS_HEADER
from otest.events import EV_PROTOCOL_RESPONSE
from otest.events import EV_REDIRECT_URL
from otest.events import EV_REQUEST
from otest.events import EV_RESPONSE
from otest.prof_util import RESPONSE

__author__ = 'rolandh'

logger = logging.getLogger(__name__)

DUMMY_URL = "https://remove.this.url/"


class ParameterError(Exception):
    pass


class Operation(operation.Operation):
    message_cls = Message


class Request(Operation):
    def expected_error_response(self, response):
        if isinstance(response, Response):  # requests response
            # don't want bytes
            _txt = response.content.decode('utf8')
            response = ErrorResponse().from_json(_txt)

        if isinstance(response, ErrorResponse):
            self.conv.events.store(EV_PROTOCOL_RESPONSE, response,
                                   sender=self.__class__.__name__)
            if response["error"] not in self.expect_error["error"]:
                raise Break("Wrong error, got {} expected {}".format(
                    response["error"], self.expect_error["error"]))
            try:
                if self.expect_error["stop"]:
                    raise Break("Stop requested after received expected error")
            except KeyError:
                pass
        else:
            self.conv.events.store(EV_FAULT, "Expected error, didn't get it")
            raise Break("Did not receive expected error")

        return response

    def map_profile(self, profile_map):
        if '.' in self.profile:
            _rt = self.profile.split('.')[RESPONSE]
        else:
            _rt = self.profile[RESPONSE]

        try:
            item = profile_map[self.__class__][_rt]
        except KeyError:
            pass
        else:
            for func, arg in item.items():
                func(self, arg)


class SyncRequest(Request):
    request_cls = None
    method = ""
    module = ""
    content_type = URL_ENCODED
    response_cls = None
    response_where = "url"
    response_type = "urlencoded"
    accept = None
    _tests = {"post": [], "pre": []}

    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)

        try:
            self.profile = self.profile.split('.')
        except AttributeError:
            pass

        self.conv.req = self
        self.tests = copy.deepcopy(self._tests)
        if self.request_cls:
            self.request = self.conv.msg_factory(self.request_cls)
        else:
            self.request = Message
        if self.response_cls:
            self.response = self.conv.msg_factory(self.response_cls)
        else:
            self.response = Message

    def do_request(self, client, url, body, ht_args):
        response = client.http_request(url, method=self.method, data=body,
                                       **ht_args)

        self.conv.events.store(EV_HTTP_RESPONSE, response,
                               sender=self.__class__.__name__)

        return response

    def handle_response(self, r, csi):
        data = self.conv.events.last_item(EV_REQUEST)
        try:
            state = data['state']
        except KeyError:
            state = ''

        if 300 < r.status_code < 400:
            resp = self.conv.entity.parse_response(
                self.response, info=r.headers['location'],
                sformat="urlencoded", state=state)
        elif r.status_code == 200:
            if "response_mode" in csi and csi["response_mode"] == "form_post":
                resp = self.response()
                forms = BeautifulSoup(r.text).findAll('form')
                for inp in forms[0].find_all("input"):
                    resp[inp.attrs["name"]] = inp.attrs["value"]
            else:
                if r.is_redirect or r.is_permanent_redirect:
                    resp = self.conv.entity.parse_response(
                        self.response, info=r.headers['location'],
                        sformat="urlencoded", state=state)
                else:
                    resp = self.conv.entity.parse_response(
                        self.response, info=r.text,
                        sformat="json", state=state)

            _ent = self.conv.entity
            if isinstance(resp, AccessTokenResponse):
                if 'id_token' in resp and isinstance(resp['id_token'], IdToken):
                    pass
                else:
                    resp.verify(keyjar=_ent.keyjar, client_id=_ent.client_id,
                                iss=_ent.provider_info['issuer'])
            else:
                resp.verify(keyjar=_ent.keyjar, client_id=_ent.client_id,
                            iss=_ent.provider_info['issuer'])

        elif r.status_code == 400:
            if r.headers['content-type'] == 'application/json':
                resp = ErrorResponse().from_json(r.text)
            else:
                resp = ErrorResponse(error='service_error',
                                     error_description=r.text)
        else:
            resp = r

        if not isinstance(resp, Response):  # Not a HTTP response
            try:
                try:
                    _id_token = resp["id_token"]
                except KeyError:
                    pass
                else:
                    if _id_token.jws_header:
                        self.conv.events.store('JWS header',
                                               _id_token.jws_header)
                    if _id_token.jwe_header:
                        self.conv.events.store('JWE header',
                                               _id_token.jwe_header)
                    if "kid" not in _id_token.jws_header and not \
                            _id_token.jws_header["alg"] == "HS256":
                        keys = self.conv.entity.keyjar.keys_by_alg_and_usage(
                            issuer=_id_token['iss'],
                            alg=_id_token.jws_header["alg"],
                            usage='sig'
                        )
                        if len(keys) > 1:
                            raise ParameterError("No 'kid' in id_token header!")

                    try:
                        if self.req_args['nonce'] != _id_token['nonce']:
                            raise ParameterError(
                                "invalid nonce! {} != {}".format(
                                    self.req_args['nonce'], _id_token['nonce']))
                    except KeyError:
                        pass

                    if not same_issuer(self.conv.info["issuer"],
                                       _id_token["iss"]):
                        raise IssuerMismatch(
                            " {} != {}".format(self.conv.info["issuer"],
                                               _id_token["iss"]))
                    self.conv.entity.id_token = _id_token
            except KeyError:
                pass

        return resp

    def run(self):
        _client = self.conv.entity

        url, body, ht_args, csi = _client.request_info(
            self.request, method=self.method, request_args=self.req_args,
            target=_client.provider_info["issuer"],
            **self.op_args)

        try:
            http_args = self.op_args["http_args"]
        except KeyError:
            http_args = ht_args
        else:
            http_args.update(ht_args)

        self.conv.events.store(EV_REQUEST, csi, sender=self.__class__.__name__)
        http_response = self.do_request(_client, url, body, http_args)

        self.catch_exception_and_error(self.handle_response, r=http_response,
                                       csi=csi)


class AsyncRequest(Request):
    request_cls = None
    method = ""
    module = ""
    content_type = URL_ENCODED
    response_cls = ""
    response_where = "url"  # if code otherwise 'body'
    response_type = "urlencoded"
    accept = None
    _tests = {"post": [], "pre": []}

    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        try:
            self.profile = self.profile.split('.')
        except AttributeError:
            pass
        self.conv.req = self
        self.tests = copy.deepcopy(self._tests)
        self.csi = None
        self.request = self.conv.msg_factory(self.request_cls)
        self.response = self.conv.msg_factory(self.response_cls)

    def run(self):
        _client = self.conv.entity

        url, body, ht_args, csi = _client.request_info(
            self.request, method=self.method, request_args=self.req_args,
            lax=True, **self.op_args)

        self.csi = csi

        self.conv.events.store(EV_REDIRECT_URL, url,
                               sender=self.__class__.__name__)
        return Redirect(str(url))

    def parse_response(self, path, inut, message_factory, response=None):
        _ctype = self.response_type
        _conv = self.conv

        if self.csi is None:
            url, body, ht_args, csi = _conv.entity.request_info(
                self.request, method=self.method, request_args=self.req_args,
                **self.op_args)

            self.csi = csi

        try:
            response_mode = self.csi["response_mode"]
        except KeyError:
            response_mode = None

        if self.request_cls == "AuthorizationRequest":
            try:
                _rt = self.csi["response_type"]
            except KeyError:
                response_where = ""
            else:
                if _rt == ["code"]:
                    response_where = "url"
                elif _rt == [""]:
                    response_where = ""
                else:
                    response_where = "fragment"
        else:
            response_where = self.response_where

        # parse the response
        if response_mode == "form_post":
            info = response
            _ctype = "dict"
        elif response_where in ["url", ""]:
            info = response
            _ctype = "dict"
        elif response_where == "fragment":
            try:
                info = response["fragment"]
            except KeyError:
                return inut.sorry_response(inut.base_url, "missing fragment ?!")
        else:  # resp_c.where == "body"
            info = response

        logger.info("Response: %s" % info)

        ev_index = _conv.events.store(EV_RESPONSE, info,
                                      sender=self.__class__.__name__)

        resp_cls = message_factory(self.response_cls)
        #  algs = _conv.entity.sign_enc_algs("id_token")
        try:
            response = _conv.entity.parse_response(
                resp_cls, info, _ctype,
                self.csi["state"],
                keyjar=_conv.entity.keyjar  # , algs=algs
            )
        except ResponseError as err:
            _conv.events.store(EV_FAULT, State(_conv.test_id, ERROR,
                                               message=err,
                                               context='parse_response'))
            return inut.err_response("run_sequence", err)
        except (VerificationError, MissingRequiredAttribute) as err:
            self.conv.events.store(EV_FAULT, err)
            inut.err_response("run_sequence", err)
            return None
        except Exception as err:
            return inut.err_response("run_sequence", err)

        logger.info("Parsed response: %s" % response.to_dict())

        _conv.events.store(EV_PROTOCOL_RESPONSE, response, ref=ev_index,
                           sender=self.__class__.__name__)

        if "id_token" in response:
            try:
                self.conv.entity.smid2sid[response['id_token']['sid']] = response['state']
            except KeyError:
                pass

        display_jwx_headers(response, _conv)

        if self.expect_error:
            self.expected_error_response(response)
        else:
            if isinstance(response, ErrorResponse):
                raise Break("Unexpected error response")


def display_jwx_headers(message, conv):
    try:
        _jws_header = message.jws_header
    except (KeyError, AttributeError):
        pass
    else:
        if _jws_header:
            conv.events.store(EV_JWS_HEADER, "{}".format(_jws_header))

    try:
        _jwe_header = message.jwe_header
    except KeyError:
        pass
    else:
        if _jwe_header:
            conv.events.store(EV_JWE_HEADER, "{}".format(_jwe_header))


def same_issuer(issuer_A, issuer_B):
    if not issuer_A.endswith("/"):
        issuer_A += "/"
    if not issuer_B.endswith("/"):
        issuer_B += "/"
    return issuer_A == issuer_B


class SyncGetRequest(SyncRequest):
    method = "GET"


class AsyncGetRequest(AsyncRequest):
    method = "GET"


class SyncPostRequest(SyncRequest):
    method = "POST"


class SyncPutRequest(SyncRequest):
    method = "PUT"


class SyncDeleteRequest(SyncRequest):
    method = "DELETE"


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj

    obj = operation.factory(name)
    if not obj:
        raise Unknown("Couldn't find the operation: '{}'".format(name))
    return obj
