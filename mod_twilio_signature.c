
/*
 * mod_twilio_signature - Apache Module for Verifying Twilio Request Signatures
 *
 * Copyright 2023 Archie L. Cobbs <archie.cobbs@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_lib.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"
#include "apr_base64.h"

// Fix libapr pollution
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "config.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_file_io.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include <ctype.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "hmac.h"

// Apache backward-compat
#ifndef AUTHN_PROVIDER_VERSION
#define AUTHN_PROVIDER_VERSION "0"
#endif

// Module definition
module AP_MODULE_DECLARE_DATA twilio_signature_module;

// Twilio signature header
#define SIGNATURE_HEADER                "X-Twilio-Signature"

// Definitions related to users file
#define WHITESPACE                      " \t\r\n\v"

// Length (in characters) of a Twilio auth token
#define AUTH_TOKEN_LENGTH               32

// "None" value for TwilioSignatureOverrideURI
#define OVERRIDE_URI_NONE               "None"

// Length (in characters) of a Twilio signature
#define SIGNATURE_LENGTH_BINARY         20                          // SHA1 = 20 bytes
#define SIGNATURE_LENGTH_BASE64         ((((SIGNATURE_LENGTH_BINARY * 8) + 23) / 24) * 4)

// Invalid auth token error message
#define INVALID_TOKEN_ERROR_MESSAGE     "invalid Twilio auth token: must contain 32 lowercase hex digits"

// One auth token in a list
struct twilsig_token {
    char                    token[AUTH_TOKEN_LENGTH];
    struct twilsig_token    *next;
};

// Per-directory configuration
struct twilsig_config {
    int                     enabled;
    const char              *override_uri;
    struct twilsig_token    *tokens;            // valid auth tokens
    struct hmac_engine      *engine;
};

// Internal functions
static void         *create_twilio_signature_dir_config(apr_pool_t *p, char *d);
static void         *merge_twilio_signature_dir_config(apr_pool_t *p, void *base_conf, void *new_conf);
static void         copy_auth_tokens(apr_pool_t *p, struct twilsig_token **dst, struct twilsig_token *src);
static int          add_auth_token(apr_pool_t *pool, struct twilsig_config *const conf, const char *auth_token);
static int          check_twilio_signature(request_rec *r);
static int          compute_signature(const struct twilsig_config *conf, const char *token, request_rec *r, u_char *hmac);
static int          compare_param_names(const void *const pair1, const void *const pair2);
static void         register_hooks(apr_pool_t *p);

// Directive handlers
static const char   *handle_auth_token_directive(cmd_parms *cmd, void *config, const char *auth_token);
static const char   *handle_auth_token_file_directive(cmd_parms *cmd, void *config, const char *auth_token);
static const char   *handle_uri_directive(cmd_parms *cmd, void *config, const char *auth_token);

///////////////////////
// MODULE DEFINITION //
///////////////////////

// Directives
static const command_rec twilio_signature_cmds[] =
{
    AP_INIT_FLAG("TwilioSignatureRequired",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(struct twilsig_config, enabled),
        ACCESS_CONF,
        "enable Twilio signature validation"),
    AP_INIT_TAKE1("TwilioSignatureAuthToken",
        handle_auth_token_directive,
        NULL,
        ACCESS_CONF,
        "Twilio auth token (32 lowercase hex digits)"),
    AP_INIT_TAKE1("TwilioSignatureAuthTokenFile",
        handle_auth_token_file_directive,
        NULL,
        ACCESS_CONF,
        "file containing Twilio auth token(s)"),
    AP_INIT_TAKE1("TwilioSignatureOverrideURI",
        handle_uri_directive,
        NULL,
        ACCESS_CONF,
        "override URI used in Twilio signature calculation"),
    { NULL }
};

// Module declaration
module AP_MODULE_DECLARE_DATA twilio_signature_module = {
    STANDARD20_MODULE_STUFF,
    create_twilio_signature_dir_config,         // create per-dir config
    merge_twilio_signature_dir_config,          // merge per-dir config
    NULL,                                       // create per-server config
    NULL,                                       // merge per-server config
    twilio_signature_cmds,                      // command apr_table_t
    register_hooks                              // register hooks
};

static void *
create_twilio_signature_dir_config(apr_pool_t *p, char *d)
{
    struct twilsig_config *conf = apr_pcalloc(p, sizeof(struct twilsig_config));

    conf->enabled = -1;
    conf->engine = hmac_engine_create(p);
    return conf;
}

static void *
merge_twilio_signature_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
    struct twilsig_config *conf = apr_pcalloc(p, sizeof(struct twilsig_config));
    struct twilsig_config *const conf1 = base_conf;
    struct twilsig_config *const conf2 = new_conf;

    // Merge "enabled" setting
    conf->enabled = conf2->enabled != -1 ? conf2->enabled : conf1->enabled;

    // Merge override URI
    if (conf2->override_uri != NULL)
        conf->override_uri = apr_pstrdup(p, conf2->override_uri);
    else if (conf1->override_uri != NULL)
        conf->override_uri = apr_pstrdup(p, conf1->override_uri);

    // Merge the auth token lists (i.e. combine them)
    copy_auth_tokens(p, &conf->tokens, conf1->tokens);
    copy_auth_tokens(p, &conf->tokens, conf2->tokens);

    // Done
    return conf;
}

static void
copy_auth_tokens(apr_pool_t *p, struct twilsig_token **dst, struct twilsig_token *src)
{
    struct twilsig_token *copy;

    while (src != NULL) {
        copy = apr_pcalloc(p, sizeof(*copy));
        memcpy(&copy->token, src->token, AUTH_TOKEN_LENGTH);
        copy->next = *dst;
        *dst = copy;
    }
}

static void
register_hooks(apr_pool_t *p)
{
    ap_hook_access_checker(check_twilio_signature, NULL, NULL, APR_HOOK_MIDDLE);
}

////////////////////////
// DIRECTIVE HANDLERS //
////////////////////////

static const char *
handle_auth_token_directive(cmd_parms *cmd, void *config, const char *auth_token)
{
    struct twilsig_config *const conf = (struct twilsig_config *)config;

    if (add_auth_token(cmd->pool, conf, auth_token) == -1)
        return apr_psprintf(cmd->pool, "%s", INVALID_TOKEN_ERROR_MESSAGE);
    return NULL;
}

static const char *
handle_auth_token_file_directive(cmd_parms *cmd, void *config, const char *path)
{
    struct twilsig_config *const conf = (struct twilsig_config *)config;
    apr_file_t *file = NULL;
    apr_status_t status;
    char buf[1024];
    int linenum;

    // Open file
    if ((status = apr_file_open(&file, path, APR_READ, 0, cmd->pool)) != 0) {
        return apr_psprintf(cmd->pool, "can't open auth token file \"%s\": %s",
          path, apr_strerror(status, buf, sizeof(buf)));
    }

    // Scan lines of file for tokens
    for (linenum = 1; apr_file_gets(buf, sizeof(buf), file) == 0; linenum++) {
        char *token;
        char *last;

        // Ignore lines starting with '#'
        if (*buf == '#')
            continue;

        // Add tokens
        while ((token = apr_strtok(buf, WHITESPACE, &last)) != NULL) {
            if (add_auth_token(cmd->pool, conf, token) == -1) {
                apr_file_close(file);
                return apr_psprintf(cmd->pool, "line %d: %s", linenum, INVALID_TOKEN_ERROR_MESSAGE);
            }
        }
    }

    // Done
    apr_file_close(file);
    return NULL;
}

static const char *
handle_uri_directive(cmd_parms *cmd, void *config, const char *uri)
{
    struct twilsig_config *const conf = (struct twilsig_config *)config;

    conf->override_uri = apr_pstrdup(cmd->pool, uri);
    return NULL;
}

////////////////////////
// INTERNAL FUNCTIONS //
////////////////////////

static int
check_twilio_signature(request_rec *r)
{
    const struct twilsig_config *conf = ap_get_module_config(r->request_config, &twilio_signature_module);
    u_char signature[SIGNATURE_LENGTH_BINARY];
    u_char hmac[SIGNATURE_LENGTH_BINARY];
    const struct twilsig_token *token;
    const char *header_value;
    const char *s;
    int token_count;

    // If a subrequest, trust the main request to have done any check already
    if (!ap_is_initial_req(r))
        return DECLINED;

    // Is signature validation required?
    if (conf->enabled < 1)
        return DECLINED;

    // Find the header
    if ((header_value = apr_table_get(r->headers_in, SIGNATURE_HEADER)) == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Twilio signature header not found");
        return HTTP_UNAUTHORIZED;
    }

    // Verify the signature looks like base 64 and has the right length
    for (s = header_value; *s != '\0'; s++) {
        if (!isalnum(*s) && *s != '=' && *s != '/' && *s != '+') {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Twilio signature contains invalid character(s)");
            return HTTP_UNAUTHORIZED;
        }
    }
    if (s - header_value != SIGNATURE_LENGTH_BASE64) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Twilio signature is invalid (length %d != %d)",
          (int)(s - header_value), SIGNATURE_LENGTH_BASE64);
        return HTTP_UNAUTHORIZED;
    }

    // Decode signature
    memset(signature, 0, sizeof(signature));                // just to be safe
    apr_base64_decode_binary(signature, header_value);

    // Verify the signature matches some token in our auth token list
    token_count = 0;
    for (token = conf->tokens; token != NULL; token = token->next) {
        token_count++;
        if (compute_signature(conf, token->token, r, hmac) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
              "Twilio signature is required but request is not compatible");
            return HTTP_UNAUTHORIZED;
        }
        if (memcmp(signature, hmac, SIGNATURE_LENGTH_BINARY) == 0)
            return DECLINED;
    }

    // Not found
    switch (token_count) {
    case 0:
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
          "Twilio signature is required but no auth tokens are configured");
        break;
    case 1:
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
          "Twilio signature does not match the configured auth token");
        break;
    default:
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
          "Twilio signature does not match any of %d configured auth tokens", token_count);
        break;
    }
    return HTTP_UNAUTHORIZED;
}

static int
compute_signature(const struct twilsig_config *conf, const char *token, request_rec *r, u_char *hmac)
{
    apr_array_header_t *params = NULL;
    struct hmac_ctx *ctx;

    // Must be GET or POST
    switch (r->method_number) {
    case M_GET:
    case M_POST:
        break;
    default:
        return -1;
    }

    // Create HMAC
    ctx = hmac_new_sha1(r->pool, conf->engine, token, strlen(token));

    // Add URI
    if (conf->override_uri && !strcasecmp(conf->override_uri, OVERRIDE_URI_NONE))
        hmac_update(ctx, conf->override_uri, strlen(conf->override_uri));
    else
        hmac_update(ctx, r->unparsed_uri, strlen(r->unparsed_uri));

    // Add POST parameters from body
    if (r->method_number == M_POST) {

        // Get parameters
        if (ap_parse_form_data(r, NULL, &params, -1, HUGE_STRING_LEN) != OK || params == NULL)
            return -1;

        // Copy array so we can modify it
        if ((params = apr_array_copy(r->pool, params)) == NULL)
            return -1;

        // Sort params by name
        qsort(params->elts, params->nelts, params->elt_size, compare_param_names);

        // Add param names and values to digest
        for (int i = 0; i < params->nelts; i++) {
            const ap_form_pair_t *const pair = (const void *)(params->elts + (i * params->elt_size));
            apr_off_t len;
            apr_size_t size;
            char *value;

            // Get field value
            apr_brigade_length(pair->value, 1, &len);
            size = (apr_size_t)len;
            value = apr_palloc(r->pool, size + 1);
            apr_brigade_flatten(pair->value, value, &size);
            value[len] = '\0';

            // Digest name and value
            hmac_update(ctx, pair->name, strlen(pair->name));
            hmac_update(ctx, value, strlen(value));
        }
    }

    // Finalize
    hmac_final(ctx, hmac);
    return 0;
}

static int
compare_param_names(const void *const ptr1, const void *const ptr2)
{
    const ap_form_pair_t *const pair1 = ptr1;
    const ap_form_pair_t *const pair2 = ptr2;

    return strcmp(pair1->name, pair2->name);
}

static int
add_auth_token(apr_pool_t *pool, struct twilsig_config *const conf, const char *auth_token)
{
    struct twilsig_token *token;
    const char *s;
    int bogus;

    // Validate token - 32 lowercase hex digits
    for (s = auth_token; *s != '\0'; s++) {
        if (!isxdigit(*s) || *s != tolower(*s)) {
            bogus = 1;
            break;
        }
    }
    if (bogus || s - auth_token != AUTH_TOKEN_LENGTH)
        return -1;

    // Add token
    token = apr_pcalloc(pool, sizeof(*token));
    memcpy(&token->token, auth_token, AUTH_TOKEN_LENGTH);
    token->next = conf->tokens;
    conf->tokens = token;

    // OK
    return 0;
}
