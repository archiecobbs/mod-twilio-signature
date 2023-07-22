## Overview

**mod\_twilio\_signature** is an [Apache web server](http://en.wikipedia.org/wiki/Apache_HTTP_Server) module for authentication of incoming Twilio HTTP requests.

Verification is performed by validating the `X-Twilio-Signature` HTTP header, which contains a base-64 encoded signature [described here](https://www.twilio.com/docs/usage/security#validating-requests).

When verification is enabled, if a request is received that either doesn't contain a `X-Twilio-Signature` HTTP header, or contains an invalid signature, then a `401 Unauthorized` error status is returned.

## Basic Configuration

Configuration is straightforward. You need to tell Apache two things:

* When to validate the signature; and
* The authentication token(s) the signature may be based on

The first item is defined using `TwilioSignatureRequired` directives inside `<Directory>` and `<Location>` tags.

The second item is defined using `TwilioSignatureAuthToken` and/or `TwilioSignatureAuthTokenFile` directives.

For example, to require auth token `e25b2c593ab0def7e23c11d83349868a` for requests to URI paths starting with `/my/twilio/webapp`:

```
<Location "/my/twilio/webapp">
    TwilioSignatureRequired yes
    TwilioSignatureAuthToken e25b2c593ab0def7e23c11d83349868a
</Location>
```

Some important notes:

* Authentication tokens are always **32 lowercase hex digits**
* `TwilioSignatureRequired` defaults to **no**

It's also possible to inherit an explicit **no** from an outer context.

**Therefore, to be safe, always specify `TwilioSignatureRequired yes` when you want to enforce signature validation**.

If you do something like this:

```
<Location "/">
    TwilioSignatureAuthToken e25b2c593ab0def7e23c11d83349868a
</Location>
```

you have not enabled validation, but you _have_ defined a valid token that will be inherited by more specific locations.

So then you would be able to just do this:

```
<Location "/more/specific/location">
    TwilioSignatureRequired yes
</Location>
```

## Advanced Configuration

### Multiple Auth Tokens

You can specify more than one auth token, for example, if multiple Twilio accounts are allowed to hit the same webhook:

```
<Location "/my/twilio/webapp">
    TwilioSignatureRequired yes
    TwilioSignatureAuthToken e25b2c593ab0def7e23c11d83349868a
    TwilioSignatureAuthToken 50c58e17c65c7aea5c48602ccc599936
    TwilioSignatureAuthToken bf566019b534f44845094713c9dc46f0
</Location>
```

Signatures can then be based on any of the tokens. However, avoid extremely long lists, because there's no way to know ahead of time which token is the right one - each token must be tried one at a time.

### Auth Tokens from a File

Putting auth tokens in config files is somewhat insecure. Instead, you can store them in a file, which can be more securely protected:

```
<Location "/my/twilio/webapp">
    TwilioSignatureRequired yes
    TwilioSignatureAuthTokenFile /etc/apache2/auth-tokens.txt
</Location>
```
File format notes:
* The file must be a text file.
* Lines that are blank, all whitespace, or start with `#` are ignored.
* Otherwise, each line must contain one or more tokens separated by whitespace.

The file(s) are read at startup and on server reload.

You may combine inline tokens via `TwilioSignatureAuthToken` and tokens from files via `TwilioSignatureAuthTokenFile`.

### Logging Level

When a request fails to authenticate, a message is logged at level INFO.

All other messages are logged at level TRACE1.

If necessary for debugging, you can increase the logging level using [Per-module logging](https://httpd.apache.org/docs/current/logs.html#permodule).

For example:

```
LogLevel twilio_signature:trace1
```

### Override URI

You can override the URI used in the signature calculation. This might be needed if there is a proxy between Twilio and Apache.

```
<Location "/private/foobar">
    TwilioSignatureRequired yes
    TwilioSignatureAuthTokenFile /etc/apache2/auth-tokens.txt
    TwilioSignatureOverrideURI https://public.website.com/some/path/foobar
</Location>
```

You can specify `TwilioSignatureOverrideURI None` to cancel any value inherited from an outer context.

### Calculation Debug

To enable logging of the details of the signature calculation algorithm for debugging purposes, use `TwilioSignatureShowCalculation on`. This will show, for each request, each authentication token tried and the data that digested to compute the signature hash at log level DEBUG.

**Warning: this is insecure because it prints authentication tokens in the log.**

### Config Merge

If you declare auth tokens in a context in which an outer context already had them, the new ones will be added to the set.

For example:

```
<Location "/foo">
    TwilioSignatureRequired yes
    TwilioSignatureAuthTokenFile /etc/apache2/secrets/tokens1.txt
</Location>
<Location "/foo/bar">
    TwilioSignatureRequired yes
    TwilioSignatureAuthTokenFile /etc/apache2/secrets/tokens2.txt
</Location>
```

Then auth tokens from both `tokens1.txt` and `tokens2.txt` are accepted inside location `/foo/bar`.

## Miscellaneous

### Compatible Requests

Twilio signatures are only defined for two types of requests: `GET` and `POST` with parameters encoded with `application/x-www-form-urlencoded` MIME type.

Validation will fail for any other types of requests.

## Download

You can download the latest buildable release here: [mod_twilio_signature-0.9.1.tar.gz](https://archie-public.s3.amazonaws.com/mod-twilio-signature/mod_twilio_signature-0.9.1.tar.gz)
