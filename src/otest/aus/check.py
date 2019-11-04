import inspect
import json
import logging
import sys

from oic.oauth2 import SUCCESSFUL
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import AuthorizationResponse

from otest.check import Check, Warnings
from otest.check import CRITICAL
from otest.check import CriticalError
from otest.check import ERROR
from otest.check import Error
from otest.check import ExpectedError
from otest.check import get_protocol_response
from otest.check import WARNING
from otest.events import EV_HTTP_RESPONSE
from otest.events import EV_PROTOCOL_RESPONSE
from otest.events import EV_RESPONSE
from otest.events import NoSuchEvent

logger = logging.getLogger(__name__)

__author__ = 'rolandh'

CONT_JSON = "application/json"
CONT_JWT = "application/jwt"


def _last_response(conv, typ, error):
    try:
        return conv.events.last_item(typ)
    except NoSuchEvent:
        logger.warning(error)
        logger.warning('\n'.join(conv.events.digest()))
        raise


def last_http_response(conv):
    return _last_response(conv, EV_HTTP_RESPONSE, 'No HTTP Response ??')


def last_raw_response(conv):
    return _last_response(conv, EV_RESPONSE, 'No Response ??')


def last_protocol_response(conv):
    return _last_response(conv, EV_PROTOCOL_RESPONSE, 'No parsed Response ??')


class MissingRedirect(CriticalError):
    """ At this point in the flow a redirect back to the client was expected.
    """
    cid = "missing-redirect"
    msg = "Expected redirect to the RP, got something else"

    def _func(self, conv=None):
        self._status = self.status
        return {"url": conv.position}


class Parse(CriticalError):
    """ Parsing the response """
    cid = "response-parse"
    errmsg = "Parse error"

    def _func(self, conv=None):
        if conv.exception:
            self._status = self.status
            err = conv.exception
            self._message = "%s: %s" % (err.__class__.__name__, err)
        else:
            _rmsg = conv.response_message
            cname = _rmsg.type()
            if conv.cresp.response != cname:
                self._status = self.status
                self._message = (
                    "Didn't get a response of the type expected:",
                    " '%s' instead of '%s', content:'%s'" % (
                        cname, conv.response_type, _rmsg))
                return {
                    "response_type": conv.response_type,
                    "url": conv.position
                }

        return {}


class CheckHTTPResponse(CriticalError):
    """
    Checks that the HTTP response status is within the 200 or 300 range.
    Also does some extra JSON checks
    """
    cid = "check-http-response"
    msg = "OP error"

    def _func(self, conv):
        res = {}
        try:
            _response = last_http_response(conv)
        except NoSuchEvent:
            return res

        if _response.status_code >= 400:
            self._status = self.status
            self._message = self.msg
            if CONT_JSON in _response.headers["content-type"]:
                try:
                    err = ErrorResponse().deserialize(_response.txt, "json")
                    self._message = err.to_json()
                except Exception:
                    res["content"] = _response.text
            else:
                res["content"] = _response.text
            res["url"] = _response.url
            res["http_status"] = _response.status_code
        elif _response.status_code in [300, 301, 302]:
            pass
        else:
            # might still be an error message
            msg = conv.events.last_item(EV_PROTOCOL_RESPONSE)
            if isinstance(msg, ErrorResponse):
                self._message = msg.to_json()
                self._status = self.status

        return res


class CheckHTTPErrorResponse(Warnings):
    """
    Checks that an error code is either 400 or 401 which are the only ones
    accepted by OAuth2/OIDC.
    """
    cid = "check-http-error-response"
    msg = "OP error"

    def _func(self, conv):
        res = {}

        try:
            _response = last_http_response(conv)
        except NoSuchEvent:
            return res

        if _response.status_code not in [200, 300, 301, 302, 400, 401]:
            self._status = self.status
            self._message = self.msg
            if CONT_JSON in _response.headers["content-type"]:
                try:
                    err = ErrorResponse().deserialize(_response.txt, "json")
                    self._message = err.to_json()
                except Exception:
                    res["content"] = _response.text
            else:
                res["content"] = _response.text
            res["url"] = _response.url
            res["http_status"] = _response.status_code

        return res


class VerifyErrorResponse(ExpectedError):
    """
    Verifies that the response received by the client via redirect was an Error
    response.
    """
    cid = "verify-err-response"
    msg = "OP error"

    def _func(self, conv):
        res = {}

        try:
            response = last_http_response(conv)
        except NoSuchEvent:
            return res

        if response.status_code == 302:
            _loc = response.headers["location"]
            if "?" in _loc:
                _query = _loc.split("?")[1]
            elif "#" in _loc:
                _query = _loc.split("#")[1]
            else:
                self._message = "Faulty error message"
                self._status = ERROR
                return

            try:
                err = ErrorResponse().deserialize(_query, "urlencoded")
                err.verify()
                # res["temp"] = err
                res["message"] = err.to_dict()
            except Exception:
                self._message = "Faulty error message"
                self._status = ERROR
        else:
            self._message = "Expected a redirect with an error message"
            self._status = ERROR

        return res


class CheckRedirectErrorResponse(ExpectedError):
    """
    Checks that the HTTP response status is outside the 200 or 300 range
    or that an error message has been received urlencoded in the form of a
    redirection.
    """
    cid = "check-redirect-error-response"
    msg = "OP error"

    def _func(self, conv):
        res = {}

        try:
            _response = last_http_response(conv)
        except NoSuchEvent:
            return res

        try:
            _loc = _response.headers["location"]
            if "?" in _loc:
                query = _loc.split("?")[1]
            elif "#" in _loc:
                query = _loc.split("#")[1]
            else:  # ???
                self._message = "Expected a redirect"
                self._status = CRITICAL
                return res
            env_id = conv.events.store(EV_RESPONSE, query)
        except (KeyError, AttributeError):
            self._message = "Expected a redirect"
            self._status = CRITICAL
            return res

        if _response.status_code == 302:
            err = ErrorResponse().deserialize(query, "urlencoded")
            try:
                err.verify()
                res["content"] = err.to_json()
                conv.events.store(EV_PROTOCOL_RESPONSE, err, env_id)
            except MissingRequiredAttribute:
                self._message = "Expected an error message"
                self._status = CRITICAL
        else:
            self._message = "Expected an error message"
            self._status = CRITICAL

        return res


class VerifyBadRequestResponse(ExpectedError):
    """
    Verifies that the OP returned a 400 Bad Request response containing a
    Error message.
    """
    cid = "verify-bad-request-response"
    msg = "OP error"

    def _func(self, conv):
        res = {}

        try:
            _response = last_http_response(conv)
        except NoSuchEvent:
            return res

        if _response.status_code == 400:
            err = ErrorResponse().deserialize(_response.text, "json")
            try:
                err.verify()
            except MissingRequiredAttribute:
                try:
                    self._status = self._kwargs["status"]
                except KeyError:
                    self._status = ERROR
                self._message = "Expected an error message"
            else:
                res["content"] = err.to_json()
        elif _response.status_code in [301, 302, 303]:
            pass
        elif _response.status_code < 300:
            _content = conv.events.last_item(EV_RESPONSE)
            err = ErrorResponse().deserialize(_content, "json")
            try:
                err.verify()
            except MissingRequiredAttribute:
                try:
                    self._status = self._kwargs["status"]
                except KeyError:
                    self._status = ERROR
                self._message = "Expected an error message"
            else:
                res["content"] = err.to_json()
            conv.events.store(EV_PROTOCOL_RESPONSE, err)
        else:
            self._message = "Expected an error message"
            try:
                self._status = self._kwargs["status"]
            except KeyError:
                self._status = CRITICAL

        return res


class VerifyRandomRequestResponse(ExpectedError):
    cid = "verify-random-request-response"
    msg = "OP error"

    def _func(self, conv):
        res = {}

        try:
            _response = last_http_response(conv)
        except NoSuchEvent:
            return res

        try:
            _content = last_raw_response(conv)
        except NoSuchEvent:
            return res

        if _response.status_code == 400:
            err = ErrorResponse().deserialize(_content, "json")
            err.verify()
            res["content"] = err.to_json()
            conv.events.store(EV_PROTOCOL_RESPONSE, err)
            pass
        elif _response.status_code in [301, 302, 303]:
            pass
        elif _response.status_code in SUCCESSFUL:
            err = ErrorResponse().deserialize(_content, "json")
            err.verify()
            res["content"] = err.to_json()
            conv.events.store(EV_PROTOCOL_RESPONSE, err)
        else:
            self._message = "Expected a 400 error message"
            self._status = CRITICAL

        return res


class VerifyUnknownClientIdResponse(ExpectedError):
    cid = "verify-unknown-client-id-response"
    msg = "OP error"

    def _func(self, conv):
        res = {}
        try:
            _response = last_http_response(conv)
        except NoSuchEvent:
            return res

        try:
            _content = last_raw_response(conv)
        except NoSuchEvent:
            return res

        if _response.status_code == 400:
            err = ErrorResponse().deserialize(_content, "json")
            err.verify()
            res["content"] = err.to_json()
            conv.events.store(EV_PROTOCOL_RESPONSE, err)
        elif _response.status_code in [301, 302, 303]:
            pass
        elif _response.status_code in SUCCESSFUL:
            err = ErrorResponse().deserialize(_content, "json")
            err.verify()
            res["content"] = err.to_json()
            conv.events.store(EV_PROTOCOL_RESPONSE, err)
        else:
            self._message = "Expected a 400 error message"
            self._status = CRITICAL

        return res


class VerifyError(Error):
    """
    Verifies that an error message was returned and also if it's the correct
    type.
    """
    cid = "verify-error"

    def _func(self, conv):
        try:
            response = last_http_response(conv)
        except NoSuchEvent:
            return {}

        if response.status_code == 400:
            try:
                item = json.loads(response.text)
            except Exception:
                self._message = "Expected an error response"
                self._status = self.status
                return {}
        else:
            try:
                item = conv.events.last_item(EV_PROTOCOL_RESPONSE)
            except IndexError:
                self._message = "Expected a message"
                self._status = CRITICAL
                return {}

            try:
                assert item.type().endswith("ErrorResponse")
            except AssertionError:
                self._message = "Expected an error response"
                self._status = self.status
                return {}

        try:
            assert item["error"] in self._kwargs["error"]
        except AssertionError:
            self._message = "Wrong type of error, got %s" % item["error"]
            self._status = WARNING

        return {}


class CheckErrorResponse(ExpectedError):
    """
    Checks that the HTTP response status is outside the 200 or 300 range
    or that an JSON encoded error message has been received
    """
    cid = "check-error-response"
    msg = "OP error"

    def _func(self, conv):
        res = {}
        # did I get one, should only be one
        try:
            _ = get_protocol_response(conv, ErrorResponse)[0]
        except ValueError:
            pass
        else:
            return res

        try:
            _response = last_http_response(conv)
        except NoSuchEvent:
            return {}

        if _response.status_code >= 400:
            content_type = _response.headers["content-type"]
            _content = _response.text
            if content_type is None:
                res["content"] = _content
            elif CONT_JSON in content_type:
                try:
                    self.err = ErrorResponse().deserialize(_content, "json")
                    self.err.verify()
                    res["content"] = self.err.to_json()
                except Exception:
                    res["content"] = _content
            else:
                res["content"] = _content
        elif _response.status_code in [300, 301, 302, 303]:
            pass
        else:
            # Should never get here
            self._message = 'Not an error message ??'
            self._status = WARNING

        return res


class VerifyErrorMessage(ExpectedError):
    """
    Checks that the last response was a JSON encoded error message
    """
    cid = "verify-error-response"
    msg = "OP error"

    def _func(self, conv):
        try:
            inst = last_protocol_response(conv)
        except NoSuchEvent:
            return {}

        try:
            assert isinstance(inst, ErrorResponse)
        except AssertionError:
            self._message = "Expected an error message"
            try:
                self._status = self._kwargs["status"]
            except KeyError:
                self._status = ERROR
        else:
            try:
                assert inst["error"] in self._kwargs["error"]
            except AssertionError:
                self._message = "Unexpected error type: %s" % inst["error"]
                self._status = WARNING
            except KeyError:
                pass

        return {}


class VerifyAuthnResponse(ExpectedError):
    """
    Checks that the last response was a JSON encoded authentication message
    """
    cid = "verify-authn-response"
    msg = "OP error"

    def _func(self, conv):
        try:
            inst = last_protocol_response(conv)
        except NoSuchEvent:
            return {}

        try:
            assert isinstance(inst, AuthorizationResponse)
        except AssertionError:
            self._message = "Expected an authorization response"
            self._status = ERROR

        return {}


class VerifyAuthnOrErrorResponse(ExpectedError):
    """
    Checks that the last response was a JSON encoded authentication or
    error message
    """
    cid = "authn-response-or-error"
    msg = "Expected authentication response or error message"
    doc = """
    :param error: The expected error messages

    Example:
        "authn-response-or-error": {
          "error": [
            "request_not_supported"
          ]
        }
    """

    def _func(self, conv):
        try:
            inst = last_protocol_response(conv)
        except NoSuchEvent:
            return {}

        try:
            assert isinstance(inst, AuthorizationResponse)
        except AssertionError:
            try:
                assert isinstance(inst, ErrorResponse)
            except AssertionError:
                self._message = "Expected an authorization or error response"
                self._status = ERROR
            else:
                try:
                    assert inst["error"] in self._kwargs["error"]
                except AssertionError:
                    self._message = "Unexpected error response: %s" % inst[
                        "error"]
                    self._status = WARNING
                except KeyError:
                    pass

        return {}


class VerifyResponse(ExpectedError):
    """
    Checks that the last response was one of a possible set of OpenID Connect
    Responses
    """
    cid = "verify-response"
    msg = "Expected OpenID Connect response"
    doc = """
    :param response_cls: Which responses the test tool has received
    :type response_cls: list of strings

    Example:
        "verify-response": {
          "response_cls": [
            "AuthorizationResponse",
            "AccessTokenResponse"
          ]
        }
    """

    def _func(self, conv):
        try:
            inst = last_protocol_response(conv)
        except NoSuchEvent:
            return {}

        try:
            _status = self._kwargs["status"]
        except KeyError:
            _status = ERROR

        if inst.__class__.__name__ not in self._kwargs["response_cls"]:
            if isinstance(inst, ErrorResponse):
                try:
                    assert inst["error"] in self._kwargs["error"]
                except AssertionError:
                    self._message = "Unexpected error response: %s" % inst[
                        "error"]
                    self._status = WARNING
                    return {}
                except KeyError:
                    pass
            else:
                self._message = "Got a %s response !?" % inst.__class__.__name__
                self._status = _status

        return {}


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    from otest.check import factory as a_factory

    return a_factory(cid)
