## Overview

**mod\_twilio\_signature** is an [Apache web server](http://en.wikipedia.org/wiki/Apache_HTTP_Server) module for authentication of incoming Twilio HTTP requests. Verification is performed by validating the `X-Twilio-Signature` HTTP header, which contains a base-64 encoded signature [described here](https://www.twilio.com/docs/usage/security#validating-requests).

If a request is received that either doesn't contain a `X-Twilio-Signature` HTTP header, or contains an invalid signature, then a `401 Unauthorized` error status is returned.

## Basic Configuration

Configuration is straightforward. You need to tell Apache two things: (a) when to require the signature; and (b) the Twilio account authentication token (i.e., secret key) from which the signature is generated.

"When to require the signature" is defined in the normal Apache way, using `<Directory>` and `<Location>` tags, etc., and by the `TwilioSignatureRequired` directive.

The auth token is specified via the `TwilioSignatureAuthToken` directive.

For example:

```
<Location /my/twilio/webapp>
    TwilioSignatureRequired yes
    TwilioSignatureAuthToken e25b2c593ab0def7e23c11d83349868a
</Location>
```

The `TwilioSignatureRequired` defaults to **no**. It's also possible to inherit an explicit **no** from an outer context when this directive is missing.

Therefore, to be safe, **always specify `TwilioSignatureRequired yes` when you want to enforce signature validation**.

## Advanced Configuration

### Multiple Auth Tokens

You can specify more than one auth token, for example, if multiple Twilio accounts are allowed to hit the same webhook:

```
<Location /my/twilio/webapp>
    TwilioSignatureRequired yes
    TwilioSignatureAuthToken e25b2c593ab0def7e23c11d83349868a
    TwilioSignatureAuthToken 50c58e17c65c7aea5c48602ccc599936
    TwilioSignatureAuthToken bf566019b534f44845094713c9dc46f0
</Location>
```

### Auth Tokens from a File

Putting auth tokens in config files is somewhat insecure. Instead, you can store them in a file, which can be more securely protected (as long as the Apache process has permission to read the file).

```
<Location /my/twilio/webapp>
    TwilioSignatureRequired yes
    TwilioSignatureAuthTokenFile /etc/apache2/secrets/auth-tokens.txt
</Location>
```

The file is a text file. Lines that are blank or start with a `#` are ignored. Otherwise, each line must contain exactly 32 hex digits.

The file is read once at startup (or after a server reload). If the file contains any bogus lines, startup fails.

Note: it is _not_ an error if the file contains zero auth tokens.

You may combine inline tokens via `TwilioSignatureAuthToken` and tokens from files via `TwilioSignatureAuthTokenFile`.

### Log Level

When a request fails to authenticate, a message is logged at level INFO. If necessary for debugging, you can increase this using [Per-module logging](https://httpd.apache.org/docs/current/logs.html#permodule).

```
LogLevel twilio_signature:warn
```

### Override URI

You can override the URI used in the signature calculation. This might be needed if there is a proxy between Twilio and Apache.

```
<Location /private/foobar>
    TwilioSignatureRequired yes
    TwilioSignatureAuthTokenFile /etc/apache2/secrets/tokens1.txt
    TwilioSignatureOverrideURI https://public.website.com/some/path/foobar
</Location>
```

You can specify `TwilioSignatureOverrideURI None` to cancel any value inherited from an outer context. The `None` is case-insensitive.

### Config Merge

If you declare auth tokens in a context in which an outer context already had them, the new ones will be added to the set.

For example:

```
<Location /foo>
    TwilioSignatureRequired yes
    TwilioSignatureAuthTokenFile /etc/apache2/secrets/tokens1.txt
</Location>
<Location /foo/bar>
    TwilioSignatureRequired yes
    TwilioSignatureAuthTokenFile /etc/apache2/secrets/tokens2.txt
</Location>
```

Then auth tokens from both `tokens1.txt` and `tokens2.txt` are accepted inside location `/foo/bar`.

To provide a safe/conservative default, if you omit the `TwilioSignatureRequired`, then it defaults to `yes`. However, this default can be overridden in a containing context. Therefore, to be safe, **you should always explicitly specify `TwilioSignatureRequired yes` if you want signature checks enabled**.
