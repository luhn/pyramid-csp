import base64
import secrets

from pyramid.events import NewResponse
from pyramid.request import RequestLocalCache
from zope.interface import Interface, implementer


def includeme(config):
    csp = ContentSecurityPolicy()
    config.registry.registerUtility(csp, IContentSecurityPolicy)
    config.add_subscriber(inject_csp, NewResponse)
    config.add_directive("add_csp_source", add_csp_source)
    config.add_request_method(add_csp_request_source, "add_csp_source")

    # Parse ``csp`` setting
    settings = config.get_settings()
    csp = settings.get("csp.policy")
    if csp:
        for directive in csp.split(";"):
            name, *sources = directive.split()
            for source in sources:
                config.add_csp_source(name, source)

    # CSP Nonce: https://content-security-policy.com/nonce/
    config.add_request_method(make_csp_nonce, "csp_nonce", reify=True)
    directives_setting = settings.get("csp.nonce_directives", "default-src")
    config.registry["csp.nonce_directives"] = [
        x.strip() for x in directives_setting.split(",")
    ]


class CSPSources:
    WILDCARD = "*"
    NONE = "'none'"
    SELF = "'self'"
    DATA = "data:"
    HTTPS = "https:"
    UNSAFE_INLINE = "'unsafe-inline'"
    UNSAFE_EVAL = "'unsafe-eval'"
    STRICT_DYNAMIC = "'strict-dynamic'"
    UNSAFE_HASHES = "'unsafe-hashes'"

    @staticmethod
    def https(domain):
        return f"https://{domain}"

    @staticmethod
    def nonce(nonce):
        return f"'nonce-{nonce}'"

    @staticmethod
    def hash(alg, h):
        if isinstance(h, bytes):
            h = base64.b64encode(h).decode("ascii")
        return f"'{alg}-{h}'"

    @classmethod
    def sha256(cls, h):
        return cls.hash("sha256", h)

    @classmethod
    def sha384(cls, h):
        return cls.hash("sha384", h)

    @classmethod
    def sha512(cls, h):
        return cls.hash("sha512", h)


class IContentSecurityPolicy(Interface):
    def add_source(directive, source):
        """
        Add a source to the given directive.

        """
        ...

    def make_csp(request):
        """
        Create a string for the CSP header.

        If CSP has no directives, returns None.

        """
        ...


@implementer(IContentSecurityPolicy)
class ContentSecurityPolicy:
    def __init__(self):
        self.directives = dict()
        self.request_directives = RequestLocalCache(lambda _: {})

    def add_source(self, directive, source):
        """
        Add a source to the given directive.  A source can be either a string
        or a callable.  The callable must accept a single positional argument
        of a request object and return either a string or ``None``.  If
        ``None`` is returned, no source will be added to the CSP directive.

        """
        sources = self.directives.setdefault(directive, [])
        sources.append(source)

    def add_request_source(self, request, directive, source):
        """
        Add a source for the given request only.  The source must be a string;
        it does not support callables like :meth:`add_source`.

        """
        directives = self.request_directives.get_or_create(request)
        directives.setdefault(directive, []).append(source)

    def get_directives(self, request):
        """
        Get CSP directives for the given request.  Directives are return as a
        dictionary of lists.

        """
        request_directives = self.request_directives.get(request, {})
        base_directives = self.directives
        directives = {}
        for key in request_directives.keys() | base_directives.keys():
            base_sources = []
            for source in base_directives.get(key, []):
                if callable(source):
                    result = source(request)
                    if result is not None:
                        base_sources.append(result)
                else:
                    base_sources.append(source)
            directives[key] = [
                *base_sources,
                *request_directives.get(key, []),
            ]
        if "default-src" not in directives:
            directives["default-src"] = [CSPSources.NONE]
        return directives

    def make_csp(self, request):
        """
        Generate a CSP string.

        """
        directives = self.get_directives(request)
        return "; ".join(
            " ".join([name, *sources])
            for (name, sources) in sorted(directives.items())
        )


def add_csp_source(config, directive, source):
    csp = config.registry.getUtility(IContentSecurityPolicy)
    return csp.add_source(directive, source)


def add_csp_request_source(request, directive, source):
    csp = request.registry.getUtility(IContentSecurityPolicy)
    return csp.add_request_source(request, directive, source)


def inject_csp(event):
    """
    Insert a CSP header into the response.  Used with the NewResponse event.

    """
    csp = event.request.registry.getUtility(IContentSecurityPolicy)
    csp_string = csp.make_csp(event.request)
    event.response.headers.setdefault("Content-Security-Policy", csp_string)


def make_csp_nonce(request):
    nonce = secrets.token_urlsafe()
    for name in request.registry["csp.nonce_directives"]:
        request.add_csp_source(name, CSPSources.nonce(nonce))
    return nonce
