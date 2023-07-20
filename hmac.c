
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

//#include <openssl/bio.h>
//#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "util.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000

struct hmac_engine {
    EVP_MAC         *hmac;
};

struct hmac_ctx {
    EVP_MAC_CTX     *ctx;
    char            digest[32];
    OSSL_PARAM      params[2];
    int             reslen;
    int             active;
};

static struct hmac_ctx *hmac_new(apr_pool_t *pool, EVP_MAC *hmac,
    const char *digest, size_t reslen, const void *key, size_t keylen);

#else   /* use older HMAC API */

struct hmac_engine {
    const EVP_MD    *mac_sha1;
    const EVP_MD    *mac_sha256;
};

struct hmac_ctx {
    HMAC_CTX        *ctx;
    const EVP_MD    *md;
    int             reslen;
    int             active;
};

static struct hmac_ctx *hmac_new(apr_pool_t *pool, const EVP_MD *md,
    size_t reslen, const void *key, size_t keylen);

#endif

struct hmac_engine *
hmac_engine_create(apr_pool_t *p)
{
    struct hmac_engine *engine;

    // Allocate structure
    if ((engine = apr_pcalloc(p, sizeof(*engine))) == NULL)
        return NULL;
    engine->pool = p;

    // Get HMAC(s)
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    if ((engine->hmac = EVP_MAC_fetch(NULL, "HMAC", NULL)) == NULL) {
        errno = ENOTSUP;
        return NULL;
    }
#else
    engine->mac_sha1 = EVP_sha1();
    engine->mac_sha256 = EVP_sha256();
#endif

    // Done
    return engine;
}

struct hmac_ctx *
hmac_new_sha1(struct hmac_engine *engine, const void *key, size_t keylen)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    return hmac_new(engine, engine->hmac, "SHA1", SHA_DIGEST_LENGTH, key, keylen);
#else
    return hmac_new(engine, engine->mac_sha1, SHA_DIGEST_LENGTH, key, keylen);
#endif
}

struct hmac_ctx *
hmac_new_sha256(struct hmac_engine *engine, const void *key, size_t keylen)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    return hmac_new(engine, engine->hmac, "SHA256", SHA256_DIGEST_LENGTH, key, keylen);
#else
    return hmac_new(engine, engine->mac_sha256, SHA256_DIGEST_LENGTH, key, keylen);
#endif
}

static struct hmac_ctx *
#if OPENSSL_VERSION_NUMBER >= 0x30000000
hmac_new(apr_pool_t *pool, EVP_MAC *hmac, const char *digest, size_t reslen, const void *key, size_t keylen)
#else
hmac_new(apr_pool_t *pool, const EVP_MD *md, size_t reslen, const void *key, size_t keylen)
#endif
{
    struct hmac_ctx *ctx;
    int r;

    if ((ctx = apr_pcalloc(pool, sizeof(*ctx))) == NULL)
        return NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    if ((ctx->ctx = EVP_MAC_CTX_new(hmac)) == NULL) {
        r = ENOMEM;
        goto fail;
    }
    apr_snprintf(ctx->digest, sizeof(ctx->digest), "%s", digest);
    ctx->params[0] = OSSL_PARAM_construct_utf8_string("digest", ctx->digest, 0);
    ctx->params[1] = OSSL_PARAM_construct_end();
#else
    if ((ctx->ctx = HMAC_CTX_new()) == NULL) {
        r = ENOMEM;
        goto fail;
    }
    ctx->md = md;
#endif
    ctx->reslen = reslen;
    ctx->active = 0;
    hmac_reset(ctx, key, keylen);

    // Register cleanup
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    apr_pool_cleanup_register(pool, ctx->ctx, EVP_MAC_CTX_free, NULL);
#else
    apr_pool_cleanup_register(pool, ctx->ctx, HMAC_CTX_free, NULL);
#endif

    // Done
    return ctx;

fail:
    errno = r;
    return NULL;
}

void
hmac_reset(struct hmac_ctx *ctx, const void *key, size_t keylen)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_MAC_init(ctx->ctx, key, keylen, ctx->params);
#else
    HMAC_Init_ex(ctx->ctx, key, keylen, ctx->md, NULL);
#endif
    ctx->active = 1;
}

void
hmac_update(struct hmac_ctx *ctx, const void *data, size_t len)
{
    assert(ctx->active);
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_MAC_update(ctx->ctx, data, len);
#else
    HMAC_Update(ctx->ctx, data, len);
#endif
}

void
hmac_final(struct hmac_ctx *ctx, u_char *result)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    size_t len;
#else
    u_int len;
#endif

    assert(ctx->active);
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_MAC_final(ctx->ctx, result, &len, ctx->reslen);
#else
    HMAC_Final(ctx->ctx, result, &len);
#endif
    assert(ctx->reslen == len);
    ctx->active = 0;
}

int
hmac_result_length(struct hmac_ctx *ctx)
{
    return ctx->reslen;
}
