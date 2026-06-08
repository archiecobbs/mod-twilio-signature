## Overview

**mod\_twilio\_signature** is an [Apache web server](http://en.wikipedia.org/wiki/Apache_HTTP_Server) module for authentication of incoming Twilio HTTP requests.

Verification is performed by validating the `X-Twilio-Signature` HTTP header, which contains a base-64 encoded signature [described here](https://www.twilio.com/docs/usage/security#validating-requests).

When verification is enabled, if a request is received that either doesn't contain a `X-Twilio-Signature` HTTP header, or the header contains an invalid signature, then a `403 Forbidden` error status is returned.

## Configuration

Configuration is straightforward. You need to tell Apache two things:

1. When to validate the signature
1. The authentication token(s) the signature may be based on

The first item is defined using the `TwilioSignatureRequired` directive.

The second item is defined using the `TwilioSignatureAuthToken` directive.

For example, to require auth token `e25b2c593ab0def7e23c11d83349868a` for requests to URI paths starting with `/my/twilio/webapp`:

```
<Location "/my/twilio/webapp">
    TwilioSignatureRequired on
    TwilioSignatureAuthToken e25b2c593ab0def7e23c11d83349868a
</Location>
```

Some important notes:

* Authentication tokens are always **32 lowercase hex digits**
* `TwilioSignatureRequired` defaults to **off**

It's also possible to inherit an explicit **off** from an outer context that overrides an explicit **on** in an even more outer context.

**Therefore, to be safe, always specify `TwilioSignatureRequired on` when you want to enforce signature validation**.

If you do something like this:

```
<Location "/">
    TwilioSignatureAuthToken e25b2c593ab0def7e23c11d83349868a
</Location>
```

you have not enabled validation, but you _have_ defined a valid token that will be inherited by more specific locations.

So in some narrower context you would then be able to just do this:

```
<Location "/more/specific/location">
    TwilioSignatureRequired on
</Location>
```

### Multiple Auth Tokens

You can specify more than one auth token, for example, if multiple Twilio accounts are allowed to hit the same webhook:

```
<Location "/my/twilio/webapp">
    TwilioSignatureRequired on
    TwilioSignatureAuthToken e25b2c593ab0def7e23c11d83349868a
    TwilioSignatureAuthToken 50c58e17c65c7aea5c48602ccc599936
    TwilioSignatureAuthToken bf566019b534f44845094713c9dc46f0
</Location>
```

Signatures can then be based on any of the tokens.

### Auth Tokens from a File

Putting auth tokens in Apache config files is somewhat insecure. Instead, you can store them in a file, which can be more securely protected:

```
<Location "/my/twilio/webapp">
    TwilioSignatureRequired on
    TwilioSignatureAuthTokenFile /etc/apache2/auth-tokens.txt
</Location>
```
File format notes:
* The file must be a text file.
* Lines that are empty, all whitespace, or start with `#` are ignored.
* Otherwise, each line must contain one or more tokens separated by whitespace.

File(s) are read at startup, and on server reload, and then the contents are cached; they are *not* read anew for each request. If you update a file, you need to reload or restart Apache to make those changes take effect.

You may freely combine inline tokens via `TwilioSignatureAuthToken` and tokens from files via `TwilioSignatureAuthTokenFile`.

### Auth Token Inheritance

If you declare auth tokens in a context in which an outer context already had them, the new ones will be added to the set.

For example:

```
<Location "/foo">
    TwilioSignatureRequired on
    TwilioSignatureAuthTokenFile /etc/apache2/secrets/tokens1.txt
</Location>
<Location "/foo/bar">
    TwilioSignatureRequired on
    TwilioSignatureAuthTokenFile /etc/apache2/secrets/tokens2.txt
</Location>
```

Then auth tokens from both `tokens1.txt` and `tokens2.txt` are accepted inside location `/foo/bar`.

### Override URI

You can override the URI used in the signature calculation. This might be needed if there is a proxy between Twilio and Apache.

```
<Location "/private/foobar">
    TwilioSignatureRequired on
    TwilioSignatureAuthTokenFile /etc/apache2/auth-tokens.txt
    TwilioSignatureOverrideURI https://public.website.com/some/path/foobar
</Location>
```

You can specify `TwilioSignatureOverrideURI None` to cancel a setting inherited from an outer context.

## Optimizing Your Configuration

### Auth Token Ordering

When there are multiple auth tokens configured in a context, there is no way for Apache to know ahead of time which token was used to compute the signature for a given request. Instead, each possible token must be tried one-at-a-time. Since this involves crytographic hashing, for performance reasons you should avoid configuring extremely long lists of auth tokens.

In any case, if multiple auth tokens are available they always tried in a well-defined order:
* In a given context, tokens are tried in the order they are specified in that context (whether inline or from a file).
* Tokens specified in an inner context are tried before tokens specified in any outer context that contains it

Finally, the same token is never tried more than once for any given request, so duplicates are not harmful.

### SMS vs. Voice Requests

Twilio signatures are calculated differently depending on:
* Whether the request was sent over HTTP or HTTPS
* Whether the Twilio callback is an SMS callback or a Voice callback
* Whether the configured URL contains an explicit port number for a default port
  * For HTTP, this is the difference between `http://example.com/path` and `http://example.com:80/path`
  * For HTTPS, this is the difference between `https://example.com/path` and `https://example.com:443/path`

**mod\_twilio\_signature** has no way of knowing those latter two pieces of information, so it may have to perform the signature calculation multiple ways before it finds a match.

To avoid that overhead, you can provide this information using either or both of the following directives:

| **Directive** | **Type** | **Value** | **Default** | **Description** |
|:--------------|:---------|:----------|:------------|:----------------|
| `TwilioSignatureCallbackType` | String  | `SMS`, `Voice`, or `Both` | `Both`| Twilio callback type(s) |
| `TwilioSignatureExplicitDefaultPorts` | String  | `Always`, `Never`, or `Maybe` | `Maybe` | Whether explicit default ports are used |

But **warning** evidence has appeared that Twilio is not following its own documentation when it comes to voice callbacks. As a workaround, anywhere you would normally want to specify `TwilioSignatureCallbackType Voice` for now you should specify `TwilioSignatureCallbackType Both` instead (or just leave it alone, as this is the default).

## Miscellaneous

### Logging

When a request fails to authenticate, a message is logged at level INFO.

All other messages are logged at level TRACE1 or lower (except for [Calculation Debug](#calculation-debug)).

If necessary for debugging, you can increase the logging level using [Per-module logging](https://httpd.apache.org/docs/current/logs.html#permodule).

For example:

```
LogLevel twilio_signature:trace1
```

### Calculation Debug

To enable logging of the details of the signature calculation algorithm for debugging purposes, use `TwilioSignatureShowCalculation on`. This will show, for each request, each authentication token tried and the data that was digested to compute the signature hash.

**Warning: this is insecure because it prints authentication tokens in the log.**

These messages are logged at log level DEBUG. To see them, you may need to add this directive:

```
LogLevel twilio_signature:debug
```

### Compatible Requests

Twilio signatures are only defined for two types of requests: `GET` and `POST` with parameters encoded with `application/x-www-form-urlencoded` MIME type.

Validation will fail for any other types of requests with `405 Method Not Allowed` or `400 Bad Request`.

### POST Body Size Limit

Signature validation of POST requests requires snooping into (but not consuming) the request payload. Since the payload data is streaming in over the network, it must be copied/cached in memory to allow it to be read more than once. To avoid resource exhaustion, this module imposes a maximum payload length of 1MB, which should be more than enough for normal Twilio requests. POST requests that exceed the limit will return a `413 Content Too Large` error and Apache will log the error `payload exceeds the Twilio signature supported limit`.

If needed, you can increase this limit using the `TwilioSignatureMaxBodySize` directive:

```
<Location "/my/twilio/webapp">
    TwilioSignatureRequired on
    TwilioSignatureAuthToken e25b2c593ab0def7e23c11d83349868a

    # Handle POST payloads up to 10MB
    TwilioSignatureMaxBodySize 10485760
</Location>
```
