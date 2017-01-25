/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __LIBFLASH_BLOCKLEVEL_ERRORS_H
#define __LIBFLASH_BLOCKLEVEL_ERRORS_H

#include <libflash/blocklevel.h>

#ifdef __SKIBOOT__
int check_rc(struct blocklevel_device *bl, int rc);
#else
static inline int check_rc(struct blocklevel_device *bl __attribute__((unused)), int rc)
{
	return rc;
}
#endif
#endif /* __LIBFLASH_BLOCKLEVEL_ERRORS_H */
