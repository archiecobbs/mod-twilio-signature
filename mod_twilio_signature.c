
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

#include "httpd.h"
#include "http_log.h"
#include "http_request.h"

#include <ctype.h>

#include "hmac.h"

// Macros
#define SIGNATURE_HEADER                "X-Twilio-Signature"                // Twilio signature header
#define WHITESPACE                      " \t\r\n\v"                         // Used when parsing auth token files
#define AUTH_TOKEN_LENGTH               32                                  // Length (in characters) of a Twilio auth token
#define OVERRIDE_URI_NONE               "None"                              // "None" value for TwilioSignatureOverrideURI
#define SIGNATURE_LENGTH_BINARY         20                                  // Length (in bytes) of Twilio SHA1 signature
#define SIGNATURE_LENGTH_BASE64         ((((SIGNATURE_LENGTH_BINARY * 8) + 23) / 24) * 4)
#define INVALID_TOKEN_ERROR_MESSAGE     "invalid Twilio auth token (must be 32 lowercase hex digits)"

// Defaults
#define DEFAULT_ENABLED                 0                                   // default for TwilioSignatureRequired
#define DEFAULT_SHOW_CALCULATION        0                                   // default for TwilioSignatureShowCalculation

// One auth token in a list
struct twilsig_token {
    char                    token[AUTH_TOKEN_LENGTH + 1];
    struct twilsig_token    *next;
};

// Module configuration
struct twilsig_config {
    int                     enabled;            // 0 = no, 1 = yes, -1 = inherit
    int                     show_calculation;   // 0 = no, 1 = yes, -1 = inherit
    const char              *override_uri;
    struct twilsig_token    *tokens;            // valid auth tokens
    struct hmac_engine      *engine;
};

// Internal functions
static void         *create_twilio_signature_dir_config(apr_pool_t *p, char *d);
static void         *merge_twilio_signature_dir_config(apr_pool_t *p, void *base_conf, void *new_conf);
static int          configure_auth_token(apr_pool_t *pool, struct twilsig_config *const conf, const char *token);
static void         add_auth_token_to_list(apr_pool_t *p, struct twilsig_token **listp, const char *token);
static int          check_twilio_signature(request_rec *r);
static int          compute_signature(const struct twilsig_config *conf, const char *token,
                        request_rec *r, apr_array_header_t *post_params, u_char *hmac);
static int          compare_param_names(const void *const ptr1, const void *const ptr2);
static int          merge_flag(int outer_flag, int inner_flag);
static int          read_flag(int flag, int defaultValue);
static void         register_hooks(apr_pool_t *p);

///////////////////////
// MODULE DEFINITION //
///////////////////////

// Directive handlers
static const char   *handle_auth_token_directive(cmd_parms *cmd, void *config, const char *token);
static const char   *handle_auth_token_file_directive(cmd_parms *cmd, void *config, const char *token);
static const char   *handle_override_uri_directive(cmd_parms *cmd, void *config, const char *token);

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
        handle_override_uri_directive,
        NULL,
        ACCESS_CONF,
        "override URI used in Twilio signature calculation"),
    AP_INIT_FLAG("TwilioSignatureShowCalculation",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(struct twilsig_config, show_calculation),
        ACCESS_CONF,
        "enable debug logging of signature calculation"),
    { NULL }
};

// Module declaration
AP_DECLARE_MODULE(twilio_signature) = {
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
    conf->show_calculation = -1;
    conf->engine = hmac_engine_create(p);
    return conf;
}

static void *
merge_twilio_signature_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
    struct twilsig_config *conf = apr_pcalloc(p, sizeof(struct twilsig_config));
    struct twilsig_config *const conf1 = base_conf;
    struct twilsig_config *const conf2 = new_conf;
    struct twilsig_token *token;

    // Merge flags
    conf->enabled = merge_flag(conf1->enabled, conf2->enabled);
    conf->show_calculation = merge_flag(conf1->show_calculation, conf2->show_calculation);

    // Merge override URI
    if (conf2->override_uri != NULL)
        conf->override_uri = apr_pstrdup(p, conf2->override_uri);
    else if (conf1->override_uri != NULL)
        conf->override_uri = apr_pstrdup(p, conf1->override_uri);

    // Merge the auth token lists by simply combining them
    for (token = conf1->tokens; token != NULL; token = token->next)
        add_auth_token_to_list(p, &conf->tokens, token->token);
    for (token = conf2->tokens; token != NULL; token = token->next)
        add_auth_token_to_list(p, &conf->tokens, token->token);

    // Done
    return conf;
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
handle_auth_token_directive(cmd_parms *cmd, void *config, const char *token)
{
    struct twilsig_config *const conf = (struct twilsig_config *)config;

    if (configure_auth_token(cmd->pool, conf, token) == -1)
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
    char *token;
    char *last;

    // Open file
    if ((status = apr_file_open(&file, path, APR_READ, 0, cmd->pool)) != 0) {
        return apr_psprintf(cmd->pool, "can't open auth token file \"%s\": %s",
          path, apr_strerror(status, buf, sizeof(buf)));
    }

    // Scan lines of file for tokens
    for (linenum = 1; apr_file_gets(buf, sizeof(buf), file) == 0; linenum++) {

        // Ignore lines starting with '#'
        if (*buf == '#')
            continue;

        // Add tokens
        while ((token = apr_strtok(buf, WHITESPACE, &last)) != NULL) {
            if (configure_auth_token(cmd->pool, conf, token) == -1) {
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
handle_override_uri_directive(cmd_parms *cmd, void *config, const char *uri)
{
    struct twilsig_config *const conf = (struct twilsig_config *)config;

    conf->override_uri = apr_pstrdup(cmd->pool, uri);
    return NULL;
}

static int
configure_auth_token(apr_pool_t *pool, struct twilsig_config *const conf, const char *token)
{
    const char *s;

    // Validate token - 32 lowercase hex digits
    for (s = token; *s != '\0'; s++) {
        if (!isxdigit(*s) || *s != tolower(*s))
            return -1;
    }
    if (s - token != AUTH_TOKEN_LENGTH)
        return -1;

    // Add token
    add_auth_token_to_list(pool, &conf->tokens, token);
    return 0;
}

////////////////////////
// INTERNAL FUNCTIONS //
////////////////////////

static int
check_twilio_signature(request_rec *r)
{
    const struct twilsig_config *conf = ap_get_module_config(r->request_config, &twilio_signature_module);
    const int show_calculation = read_flag(conf->show_calculation, DEFAULT_SHOW_CALCULATION);
    apr_array_header_t *post_params = NULL;
    u_char signature[SIGNATURE_LENGTH_BINARY];
    u_char hmac[SIGNATURE_LENGTH_BINARY];
    const struct twilsig_token *token;
    const char *header_value;
    const char *s;
    int token_count;

    // If a subrequest, trust the main request to have done any check already
    if (!ap_is_initial_req(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Twilio signature verification skipped for subrequest");
        return DECLINED;
    }

    // Is signature validation required?
    if (read_flag(conf->enabled, DEFAULT_ENABLED)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Twilio signature verification disabled");
        return DECLINED;
    }

    // Find the header
    if ((header_value = apr_table_get(r->headers_in, SIGNATURE_HEADER)) == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Twilio signature required but no header found");
        return HTTP_UNAUTHORIZED;
    }

    // Verify the signature looks like base 64 and has the right length
    for (s = header_value; *s != '\0'; s++) {
        if (!isalnum(*s) && *s != '=' && *s != '/' && *s != '+') {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
              "Twilio signature contains an invalid (non-base64) character at offset %d", (int)(s - header_value));
            return HTTP_UNAUTHORIZED;
        }
    }
    if (s - header_value != SIGNATURE_LENGTH_BASE64) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Twilio signature has the wrong length %d != %d",
          (int)(s - header_value), SIGNATURE_LENGTH_BASE64);
        return HTTP_UNAUTHORIZED;
    }

    // Decode the signature
    memset(signature, 0, sizeof(signature));                // just to be safe
    apr_base64_decode_binary(signature, header_value);

    // For POST requests, extract the name/value pairs from the body
    if (r->method_number == M_POST) {

        // Get POST parameters
        if (ap_parse_form_data(r, NULL, &post_params, -1, HUGE_STRING_LEN) != OK || post_params == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Twilio signature required but request is not compatible");
            return -1;
        }

        // Sort params by name
        qsort(post_params->elts, post_params->nelts, post_params->elt_size, compare_param_names);
    }

    // Verify the signature matches some token in our auth token list
    token_count = 0;
    if (show_calculation)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "twilio-signature: checking auth tokens for signature \"%s\"", header_value);
    for (token = conf->tokens; token != NULL; token = token->next) {
        token_count++;
        if (compute_signature(conf, token->token, r, post_params, hmac) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Twilio signature required but request is not compatible");
            return HTTP_UNAUTHORIZED;
        }
        if (memcmp(signature, hmac, SIGNATURE_LENGTH_BINARY) == 0) {
            if (show_calculation) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "twilio-signature: signature \"%s\" matched token #%d", header_value, token_count);
            }
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Twilio signature verified (via token #%d)", token_count);
            return DECLINED;
        }
    }
    if (show_calculation) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
          "twilio-signature: signature \"%s\" failed to match %d token(s)", header_value, token_count);
    }

    // Not found
    switch (token_count) {
    case 0:
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
          "Twilio signature required but no auth tokens are configured");
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
compute_signature(const struct twilsig_config *conf, const char *token,
    request_rec *r, apr_array_header_t *post_params, u_char *hmac)
{
    const int show_calculation = read_flag(conf->show_calculation, DEFAULT_SHOW_CALCULATION);
    const char *query_string;
    struct hmac_ctx *ctx;

    // Debug
    if (show_calculation)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "twilio-signature: computing signature using token \"%s\"", token);

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

    // Digest the URI
    if (conf->override_uri && !strcasecmp(conf->override_uri, OVERRIDE_URI_NONE)) {

        // Digest the override URI
        if (show_calculation)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "twilio-signature: digest URI \"%s\"", conf->override_uri);
        hmac_update(ctx, conf->override_uri, strlen(conf->override_uri));

        // Add the query string from *this* request (if any)
        query_string = strrchr(r->unparsed_uri, '?');
        if (query_string != NULL) {
            if (show_calculation)
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "twilio-signature: digest query \"%s\"", query_string);
            hmac_update(ctx, query_string, strlen(query_string));
        }
    } else {
        if (show_calculation)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "twilio-signature: digest URI \"%s\"", r->unparsed_uri);
        hmac_update(ctx, r->unparsed_uri, strlen(r->unparsed_uri));
    }

    // Add POST parameters from body
    if (post_params != NULL) {
        for (int i = 0; i < post_params->nelts; i++) {
            const ap_form_pair_t *const param = (const void *)(post_params->elts + (i * post_params->elt_size));
            apr_size_t size;
            apr_off_t len;
            char *value;

            // Get field value
            apr_brigade_length(param->value, 1, &len);
            size = (apr_size_t)len;
            value = apr_palloc(r->pool, size + 1);
            apr_brigade_flatten(param->value, value, &size);
            value[size] = '\0';

            // Digest name and value
            if (show_calculation) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "twilio-signature: digest name \"%s\"", param->name);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "twilio-signature: digest value \"%s\"", value);
            }
            hmac_update(ctx, param->name, strlen(param->name));
            hmac_update(ctx, value, strlen(value));
        }
    }

    // Finalize
    hmac_final(ctx, hmac);
    if (show_calculation) {
        char base64[SIGNATURE_LENGTH_BASE64 + 1];

        apr_base64_encode(base64, (char *)hmac, SIGNATURE_LENGTH_BINARY);
        base64[SIGNATURE_LENGTH_BASE64] = '\0';
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
          "twilio-signature: signature using token \"%s\" is "
          "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
          " -> \"%s\"",
          token,
          hmac[ 0], hmac[ 1], hmac[ 2], hmac[ 3], hmac[ 4],
          hmac[ 5], hmac[ 6], hmac[ 7], hmac[ 8], hmac[ 9],
          hmac[10], hmac[11], hmac[12], hmac[13], hmac[14],
          hmac[15], hmac[16], hmac[17], hmac[18], hmac[19],
          base64);
    }

    // Done
    return 0;
}

static int
compare_param_names(const void *const ptr1, const void *const ptr2)
{
    const ap_form_pair_t *const param1 = ptr1;
    const ap_form_pair_t *const param2 = ptr2;

    return strcmp(param1->name, param2->name);
}

static void
add_auth_token_to_list(apr_pool_t *p, struct twilsig_token **listp, const char *token)
{
    struct twilsig_token *copy;

    copy = apr_pcalloc(p, sizeof(*copy));
    apr_cpystrn(copy->token, token, sizeof(copy->token));
    copy->next = *listp;
    *listp = copy;
}

static int
merge_flag(int outer_flag, int inner_flag)
{
    return inner_flag != -1 ? inner_flag : outer_flag;
}

static int
read_flag(int flag, int defaultValue)
{
    switch (flag) {
    case -1:
        return defaultValue;
    default:
        return flag;
    }
}
