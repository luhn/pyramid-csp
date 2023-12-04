import secrets
from unittest.mock import Mock

import pytest
from pyramid.config import Configurator
from pyramid.events import NewResponse
from pyramid.response import Response
from pyramid.scripting import prepare
from pyramid.testing import DummyRequest
from pyramid.testing import testConfig as _testConfig
from webtest import TestApp

from pyramid_csp import (
    ContentSecurityPolicy,
    CSPSources,
    IContentSecurityPolicy,
)


@pytest.fixture
def config():
    with _testConfig() as config:
        config.include("pyramid_csp")
        yield config


@pytest.fixture
def config_csp(config):
    return config.registry.getUtility(IContentSecurityPolicy)


@pytest.fixture
def real_request(config):
    with prepare(registry=config.registry) as env:
        yield env["request"]


# Test CSPSources


def test_csp_sources_https():
    assert CSPSources.https("example.com") == "https://example.com"


def test_csp_sources_nonce():
    assert CSPSources.nonce("foobar") == "'nonce-foobar'"


def test_csp_sources_hash():
    assert CSPSources.hash("sha256", "foobar") == "'sha256-foobar'"


def test_csp_sources_hash_binary():
    assert CSPSources.hash("sha256", b"foobar") == "'sha256-Zm9vYmFy'"


def test_csp_sources_sha256():
    assert CSPSources.sha256("foobar") == "'sha256-foobar'"


def test_csp_sources_sha384():
    assert CSPSources.sha384("foobar") == "'sha384-foobar'"


def test_csp_sources_sha512():
    assert CSPSources.sha512("foobar") == "'sha512-foobar'"


# Unit test ContentSecurityPolicy


def test_csp():
    request = DummyRequest()
    csp = ContentSecurityPolicy()
    csp.add_source("default-src", CSPSources.UNSAFE_INLINE)
    csp.add_source("script-src", CSPSources.DATA)
    csp.add_source("script-src", CSPSources.SELF)
    assert csp.get_directives(request) == {
        "default-src": [CSPSources.UNSAFE_INLINE],
        "script-src": [CSPSources.DATA, CSPSources.SELF],
    }


def test_csp_no_default():
    request = DummyRequest()
    csp = ContentSecurityPolicy()
    csp.add_source("script-src", CSPSources.UNSAFE_INLINE)
    assert csp.get_directives(request) == {
        "default-src": [CSPSources.NONE],
        "script-src": [CSPSources.UNSAFE_INLINE],
    }


def test_csp_callable_source():
    request = DummyRequest()
    source = Mock(return_value="foobar")
    csp = ContentSecurityPolicy()
    csp.add_source("default-src", source)
    assert csp.get_directives(request) == {
        "default-src": ["foobar"],
    }
    source.assert_called_once_with(request)


def test_csp_request_source():
    request = DummyRequest()
    csp = ContentSecurityPolicy()
    csp.add_source("default-src", CSPSources.UNSAFE_INLINE)
    csp.add_source("script-src", CSPSources.DATA)
    csp.add_request_source(request, "script-src", CSPSources.SELF)
    assert csp.get_directives(request) == {
        "default-src": [CSPSources.UNSAFE_INLINE],
        "script-src": [CSPSources.DATA, CSPSources.SELF],
    }


def test_csp_make_csp():
    request = DummyRequest()
    csp = ContentSecurityPolicy()
    csp.add_source("default-src", CSPSources.UNSAFE_INLINE)
    csp.add_source("script-src", CSPSources.DATA)
    csp.add_request_source(request, "script-src", CSPSources.SELF)
    assert csp.make_csp(request) == (
        "default-src 'unsafe-inline'; " "script-src data: 'self'"
    )


# Test adding CSP sources and injecting into response


def test_add_csp_source(config, config_csp):
    request = DummyRequest()
    config.add_csp_source("default-src", CSPSources.UNSAFE_INLINE)
    assert config_csp.get_directives(request) == {
        "default-src": [CSPSources.UNSAFE_INLINE],
    }


def test_add_csp_request_source(config, config_csp, real_request):
    real_request.add_csp_source("default-src", CSPSources.UNSAFE_INLINE)
    assert config_csp.get_directives(real_request) == {
        "default-src": [CSPSources.UNSAFE_INLINE],
    }


def test_inject_csp(config):
    request = DummyRequest()
    response = Response()
    config.add_csp_source("default-src", CSPSources.UNSAFE_INLINE)
    config.registry.notify(NewResponse(request, response))
    assert (
        response.headers["Content-Security-Policy"]
        == "default-src 'unsafe-inline'"
    )


# Test nonce


def test_make_csp_none(monkeypatch, config, config_csp, real_request):
    monkeypatch.setattr(secrets, "token_urlsafe", Mock(return_value="foobar"))
    assert real_request.csp_nonce == "foobar"
    assert config_csp.get_directives(real_request) == {
        "default-src": [CSPSources.nonce("foobar")],
    }


def test_nonce_directives(monkeypatch):
    monkeypatch.setattr(secrets, "token_urlsafe", Mock(return_value="foobar"))
    settings = {
        "csp.nonce_directives": "default-src, script-src",
    }
    with _testConfig(settings=settings) as config:
        config.include("pyramid_csp")
        csp = config.registry.getUtility(IContentSecurityPolicy)
        with prepare(registry=config.registry) as env:
            request = env["request"]
            assert request.csp_nonce == "foobar"
            csp.get_directives(request) == {
                "default-src": [CSPSources.nonce("foobar")],
                "script-src": [CSPSources.nonce("foobar")],
            }


# Test includeme function


def test_csp_setting():
    settings = {
        "csp": "default-src 'unsafe-inline' data:; script-src 'unsafe-eval'",
    }
    with _testConfig(settings=settings) as config:
        config.include("pyramid_csp")
        csp = config.registry.getUtility(IContentSecurityPolicy)
        request = DummyRequest()
        csp.get_directives(request) == {
            "default-src": [CSPSources.UNSAFE_INLINE, CSPSources.DATA],
            "script-src": [CSPSources.UNSAFE_EVAL],
        }


# Integration test


def test_integration():
    def hello(context, request):
        body = f"""<!DOCTYPE html>
<html>
    <head>
        <title>Foobar</title>
        <script nonce="{ request.csp_nonce }">alert("Hello world!")</script>
        <style nonce="{ request.csp_nonce }">h1 {{ color: red; }}</style>
    </head>
    <body>
        <h1>Hello world!</h1>
    </body>
<html>
"""
        return Response(body=body, content_type="text/html")

    settings = {"csp": "default-src https://example.com"}
    with Configurator(settings=settings) as config:
        config.include("pyramid_csp")
        config.add_route("index", "/")
        config.add_view(hello, route_name="index")

    app = TestApp(config.make_wsgi_app())
    response = app.get("/")
    nonce = response.html.script["nonce"]
    assert response.html.style["nonce"] == nonce
    assert response.headers["Content-Security-Policy"] == (
        f"default-src https://example.com 'nonce-{nonce}'"
    )
