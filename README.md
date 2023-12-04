# pyramid-csp

`pyramid-csp` is a simple Pyramid add-on for adding a `Content-Security-Policy` header your HTTP responses

For more information on Content Security Policies, see https://content-security-policy.com/

## Setup

There are two ways of including `pyramid-csp` in your application:

The first is adding `pyramid_csp` to the `pyramid.includes` section of your application settings.

```
[app:main]
pyramid.includes = pyramid_csp
```

The second is using the `Configurator.include` function.

```python
config.include("pyramid.csp")
```

## Basic Usage

The most basic usage of `pyramid-csp` is to set the `csp.policy` setting.
This setting should be a valid CSP and will be added to the response headers.

```
[app:main]
csp.policy = default-src https://example.com
```

```
>> curl -i http://localhost:8000
...
Content-Security-Policy: default-src https://example.com
...
```

You can also create a policy by programmatically adding sources with the `add_csp_source` configuration method.
(This will work in addition to the `csp.policy` setting.)
The first argument is the directive name

```python
config.add_csp_source("default-src", "'self'")
```

```
>> curl -i http://localhost:8000
...
Content-Security-Policy: default-src https://example.com 'self'
...
```

The request object also contains an `add_csp_source` method,
which works the same as the configurator method but will only add the source for that request.

```python
def myview(context, request):
    nonce = secrets.token_urlsafe()
    request.add_csp_source("default-src", f"'nonce-{nonce}'")
    return Response(body="<h1>Hello</h1>", content_type="text/html")
```

**Note:** If no sources are defined for the `default-src` directive, `'none'` is automatically added.

## Preset Sources

`pyramid-src` provides the `CSPSources` object, which contains several preset sources.
For example:

```python
from pyramid_csp import CSPSources


def includeme(config):
    config.add_csp_source("default-src", CSPSources.UNSAFE_EVAL)
```

The `CSPSources` object has the following properties:

- `WILDCARD` — `*`
- `NONE` — `'none'`
- `SELF` — `'self'`
- `DATA` — `data:`
- `HTTPS` — `https:`
- `UNSAFE_INLINE` — `'unsafe-inline'`
- `UNSAFE_EVAL` — `'unsafe-eval'`
- `STRICT_DYNAMIC` — `'strict-dynamic'`
- `UNSAFE_HASHES` — `'unsafe-hashes'`

The object also offers several methods for generating sources:

- `https(domain)` — `https://{domain}`
- `nonce(nonce)` — `'nonce-{nonce}'`
- `hash(alg, h)` — `'{alg}-{h}'`
  (`h` should be a binary hash digest or a base64-encoded string.
  If binary, it will be base64-encoded.)
- `sha256(h)` — `'sha256-{h}'`
- `sha384(h)` — `'sha384-{h}'`
- `sha512(h)` — `'sha512-{h}'`

## Nonces

`pyramid-csp` adds a `csp_nonce` property to the request object,
containing a crytographically secure random nonce token.
If accessed, the nonce token will be added to the CSP.


```python
def myview(context, request):
    body = '<script nonce="{ request.csp_nonce }">alert("Hello!");</script>'
    return Response(body=body, content_type="text/html")
```

```
>> curl -i http://localhost:8000/
...
Content-Security-Policy: default-src 'nonce-ZtynG2MXgOPkqWgHyqf8wrR8jOeprIA2qDMKJuOfEXw'
...
<script nonce="ZtynG2MXgOPkqWgHyqf8wrR8jOeprIA2qDMKJuOfEXw">alert("Hello!")</script>
```

By default, the nonce will only be added to the `default-src` directive.
To add it to a different directive, use the `csp.nonce_directives` setting.
Multiple directives can be separated with a comma.

```
[app:main]
csp.nonce_directives = script-src, style-src
```

```python
def myview(context, request):
    body = '<script nonce="{ request.csp_nonce }">alert("Hello!");</script>'
    return Response(body=body, content_type="text/html")
```

```
>> curl -i http://localhost:8000/
...
Content-Security-Policy: default-src 'none'; script-src 'nonce-vyjGpdvTnH6x7-eL-RvVMmxx4KNMTfX9WoLdmgijv2c'; script-src 'nonce-vyjGpdvTnH6x7-eL-RvVMmxx4KNMTfX9WoLdmgijv2c'
...
<script nonce="vyjGpdvTnH6x7-eL-RvVMmxx4KNMTfX9WoLdmgijv2c">alert("Hello!")</script>
```

For more information CSP nonces, see https://content-security-policy.com/nonce/
