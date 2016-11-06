/* Copyright 2013-2014 IBM Corp.
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

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <opal.h>
#include <libflash/mbox-flash.h>
#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <libflash/blocklevel.h>
#include <ast.h>

#include "astbmc.h"

int pnor_init(void)
{
	struct blocklevel_device *bl = NULL;
	int rc;

	rc = mbox_flash_init(0x0e000000, 0, &bl);
	if (rc) {
		prerror("PLAT: Failed to open init PNOR driver\n");
		goto fail;
	}

	rc = flash_register(bl);
	if (!rc)
		return 0;

 fail:
	if (bl)
		mbox_flash_exit(bl);

	return rc;
}
