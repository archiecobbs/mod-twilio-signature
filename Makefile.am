
#
# mod_twilio_signature - Apache Module for Verifying Twilio Request Signatures
#
# Copyright 2023 Archie L. Cobbs <archie.cobbs@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

all-local:    module

module: mod_twilio_signature.c hmac.c
		if test "$(srcdir)" != "."; then $(CP) $(srcdir)/mod_twilio_signature.c .; fi
		$(APXS) -c -D_REENTRANT `echo $(GCC_WARN_FLAGS) | sed 's/ -/ -Wc,-/g'` -l crypto $^

install-exec-local: module
		mkdir -p "$(DESTDIR)`$(APXS) -q LIBEXECDIR`"
		$(APXS) -S LIBEXECDIR="$(DESTDIR)`$(APXS) -q LIBEXECDIR`" -i mod_twilio_signature.la

install-exec-hook:
		test -z "$(STRIP)" || $(STRIP) $(DESTDIR)`$(APXS) -q LIBEXECDIR`/mod_twilio_signature.so

noinst_HEADERS=     hmac.h

CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

EXTRA_DIST=         CHANGES LICENSE README.md mod_twilio_signature.c hmac.c
