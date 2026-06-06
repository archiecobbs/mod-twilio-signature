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
#include "apr_buckets.h"

// Fix libapr pollution
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "config.h"

#include "httpd.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"

#include "payload.h"

// Definitions
#define INPUT_FILTER_NAME               "PAYLOAD_FILTER"

// Internal function declarations
static apr_status_t     payload_filter_func(ap_filter_t *f,
                            apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);

// Internal variables
static int initialized;

// Public functions

int
payload_init(void)
{
    if (!initialized) {
        if (ap_register_input_filter(INPUT_FILTER_NAME, payload_filter_func, NULL, AP_FTYPE_RESOURCE) == NULL)
            return ap_map_http_request_error(APR_ENOMEM, HTTP_INTERNAL_SERVER_ERROR);
        initialized = 1;
    }
    return OK;
}

int
payload_read(request_rec *r, apr_read_type_e block, struct payload_copy **payloadp, apr_size_t max_length)
{
    struct payload_copy *payload;
    apr_bucket_brigade *bb;
    char *data = NULL;
    apr_size_t length;
    apr_status_t rv;

    // Get the request payload
    if ((bb = apr_brigade_create(r->pool, r->connection->bucket_alloc)) == NULL)
        return ap_map_http_request_error(APR_ENOMEM, HTTP_INTERNAL_SERVER_ERROR);
    if ((rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, block, HUGE_STRING_LEN)) != APR_SUCCESS
      && !APR_STATUS_IS_EOF(rv))
        return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);

    // Read it into memory
    length = max_length + 1;
    if ((rv = apr_brigade_pflatten(bb, &data, &length, r->pool)) != APR_SUCCESS)
        return ap_map_http_request_error(rv, HTTP_INTERNAL_SERVER_ERROR);

    // Check for overflow
    if (length > max_length) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Request payload exceeds the specified limit %" APR_SIZE_T_FMT, max_length);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    // Return a holder for the payload
    payload = apr_palloc(r->pool, sizeof(*payload));
    payload->data = data;
    payload->length = length;

    // Done
    *payloadp = payload;
    return OK;
}

int
payload_prepend(request_rec *r, struct payload_copy *payload)
{
    // Prepend an input filter which will prepend the payload data
    if (ap_add_input_filter(INPUT_FILTER_NAME, payload, r, r->connection) == NULL)
        return HTTP_INTERNAL_SERVER_ERROR;

    // Done
    return OK;
}

// Internal functions

static apr_status_t
payload_filter_func(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    const struct payload_copy *const payload = f->ctx;
    apr_bucket *bucket;
    ap_filter_t *next;

    // Create a new bucket containing the payload data
    if ((bucket = apr_bucket_pool_create(payload->data, payload->length, f->r->pool, f->r->connection->bucket_alloc)) == NULL)
        return ap_map_http_request_error(APR_ENOMEM, HTTP_INTERNAL_SERVER_ERROR);

    // Prepend it to the bucket brigade
#pragma GCC diagnostic push "-Wcast-qual"
#pragma GCC diagnostic ignored "-Wcast-qual"
    APR_BRIGADE_INSERT_HEAD(bb, bucket);
#pragma GCC diagnostic pop "-Wcast-qual"

    // Remove this filter, as our work is now done
    next = f->next;
    ap_remove_input_filter(f);

    // Proceed
    return ap_get_brigade(next, bb, mode, block, readbytes);
}
