
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

struct hmac_engine;
struct hmac_ctx;

extern struct hmac_engine *hmac_engine_create(apr_pool_t *p);
extern struct hmac_ctx *hmac_new_sha1(apr_pool_t *p, struct hmac_engine *engine, const void *key, size_t keylen);
extern struct hmac_ctx *hmac_new_sha256(apr_pool_t *p, struct hmac_engine *engine, const void *key, size_t keylen);
extern void hmac_reset(struct hmac_ctx *ctx, const void *key, size_t keylen);
extern void hmac_update(struct hmac_ctx *ctx, const void *data, size_t len);
extern void hmac_final(struct hmac_ctx *ctx, u_char *result);
extern int hmac_result_length(struct hmac_ctx *ctx);
