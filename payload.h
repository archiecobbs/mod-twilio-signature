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

/*
 * This provides a way to "snoop" on the payload of a request. You do this by first reading it into memory via payload_read().
 * The problem is that now you have consumed it, so the normal Apache processing won't see it. To fix that, invoke
 * payload_prepend() to push it back onto the front of the payload bucket brigade.
 *
 * You can also use payload_prepend() to prepend payload data for any other reason. Obviously this needs to be done prior
 * to the point where other parts of Apache begin reading it.
 *
 * Before using this functionality, payload_init() must be invoked.
 */

// A copy of a request payload
struct payload_copy {
    const void              *data;
    apr_size_t              length;
};

// Functions
extern apr_status_t     payload_init(void);
extern apr_status_t     payload_read(request_rec *r,
                            apr_read_type_e block, struct payload_copy **payloadp, apr_size_t max_length);
extern apr_status_t     payload_prepend(request_rec *r, struct payload_copy *payload);
