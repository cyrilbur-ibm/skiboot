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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include <libflash/libflash.h>
#include <libflash/libflash-priv.h>

#include "stubs.h"
#include "mbox-server.h"

#define zalloc(n) calloc(1, n)
#define __unused          __attribute__((unused))

#undef pr_fmt

#include "../libflash.c"
#include "../mbox-flash.c"
#include "../ecc.c"
#include "../blocklevel.c"

#undef pr_fmt
#define pr_fmt(fmt) "MBOX-PROXY: " fmt

/* client interface */

#include "../../include/lpc-mbox.h"

#define ERR(...) FL_DBG(__VA_ARGS__)

static int run_flash_test(struct blocklevel_device *bl)
{
	struct mbox_flash_data *mbox_flash;
	char hello[] = "Hello World";
	uint32_t erase_granule;
	uint64_t total_size;
	const char *name;
	uint16_t *test;
	char *tmp;
	int i, rc;

	mbox_flash = container_of(bl, struct mbox_flash_data, bl);

	/*
	 * Do something first so that if it has been reset it does that
	 * before we check versions
	 */
	rc = blocklevel_get_info(bl, &name, &total_size, &erase_granule);
	if (rc) {
		ERR("blocklevel_get_info() failed with err %d\n", rc);
		return 1;
	}
	if (total_size != mbox_server_total_size()) {
		ERR("Total flash size is incorrect: 0x%08lx v 0x%08x\n",
				total_size, mbox_server_total_size());
		return 1;
	}
	if (erase_granule != mbox_server_erase_granule()) {
		ERR("Erase granule is incorrect\n");
		return 1;
	}


	/* Sanity check that mbox_flash has inited correctly */
	if (mbox_flash->version != mbox_server_version()) {
		ERR("MBOX Flash didn't agree with the server version\n");
		return 1;
	}
	if (mbox_flash->version == 1 && mbox_flash->shift != 12) {
		ERR("MBOX Flash version 1 isn't using a 4K shift\n");
		return 1;
	}

	mbox_server_memset(0xff);

	test = malloc(0x10000 * 2);

	/* Make up a test pattern */
	for (i = 0; i < 0x10000; i++)
		test[i] = i;

	/* Write 64k of stuff at 0 and at 128k */
	printf("Writing test patterns...\n");
	rc = blocklevel_write(bl, 0, test, 0x10000);
	if (rc) {
		ERR("blocklevel_write(0, 0x10000) failed with err %d\n", rc);
		return 1;
	}
	rc = blocklevel_write(bl, 0x20000, test, 0x10000);
	if (rc) {
		ERR("blocklevel_write(0x20000, 0x10000) failed with err %d\n", rc);
		return 1;
	}

	if (mbox_server_memcmp(0, test, 0xfffc)) {
		ERR("Test pattern mismatch !\n");
		return 1;
	}

	/* Write "Hello world" straddling the 64k boundary */
	printf("Writing test string...\n");
	rc = blocklevel_write(bl, 0xfffc, hello, sizeof(hello));
	if (rc) {
		ERR("blocklevel_write(0xfffc, %s, %lu) failed with err %d\n",
				hello, sizeof(hello), rc);
		return 1;
	}

	/* Check result */
	if (mbox_server_memcmp(0xfffc, hello, sizeof(hello))) {
		ERR("Test string mismatch!\n");
		return 1;
	}

	/* Erase granule is 0x100, this shouldn't succeed */
	rc = blocklevel_erase(bl, 0, 0x50);
	if (!rc) {
		ERR("blocklevel_erase(0, 0x50) didn't fail!\n");
		return 1;
	}

	/* Check it didn't silently erase */
	if (mbox_server_memcmp(0, test, 0xfffc)) {
		ERR("Test pattern mismatch !\n");
		return 1;
	}

	/*
	 * For v1 protocol this should NOT call MARK_WRITE_ERASED!
	 * The server MARK_WRITE_ERASED will call exit(1) if it gets a
	 * MARK_WRITE_ERASED and version == 1
	 */
	rc = blocklevel_erase(bl, 0, 0x1000);
	if (rc) {
		ERR("blocklevel_erase(0, 0x1000) failed with err %d\n", rc);
		return 1;
	}

	/*
	 * Version 1 doesn't specify that the buffer actually becomes 0xff
	 * It is up to the daemon to do what it wants really - there are
	 * implementations that do nothing but writes to the same region
	 * work fine
	 */

	/* This check is important for v2 */
	/* Check stuff got erased */
	tmp = malloc(0x2000);
	if (mbox_server_version() > 1) {
		if (!tmp) {
			ERR("malloc(0x1000) failed\n");
			return 1;
		}
		memset(tmp, 0xff, 0x1000);
		if (mbox_server_memcmp(0, tmp, 0x1000)) {
			ERR("Buffer not erased\n");
			rc = 1;
			goto out;
		}
	}

	/* Read beyond the end of flash */
	rc = blocklevel_read(bl, total_size, tmp, 0x1000);
	if (!rc) {
		ERR("blocklevel_read(total_size, 0x1000) (read beyond the end) succeeded\n");
		goto out;
	}

	/* Test some simple write/read cases, avoid first page */
	rc = blocklevel_write(bl, 0x2000, test, 0x800);
	if (rc) {
		ERR("blocklevel_write(0x2000, 0x800) failed with err %d\n", rc);
		goto out;
	}
	rc = blocklevel_write(bl, 0x2800, test, 0x800);
	if (rc) {
		ERR("blocklevel_write(0x2800, 0x800) failed with err %d\n", rc);
		goto out;
	}

	rc = mbox_server_memcmp(0x2000, test, 0x800);
	if (rc) {
		ERR("%s:%d mbox_server_memcmp miscompare\n", __FILE__, __LINE__);
		goto out;
	}
	rc = mbox_server_memcmp(0x2800, test, 0x800);
	if (rc) {
		ERR("%s:%d mbox_server_memcmp miscompare\n", __FILE__, __LINE__);
		goto out;
	}

	/* Great so the writes made it, can we read them back? Do it in
	 * four small reads */
	for (i = 0; i < 4; i++) {
		rc = blocklevel_read(bl, 0x2000 + (i * 0x400), tmp + (i * 0x400), 0x400);
		if (rc) {
			ERR("blocklevel_read(0x%08x, 0x400) failed with err %d\n",
					0x2000 + (i * 0x400), rc);
			goto out;
		}
	}
	rc = memcmp(test, tmp, 0x800);
	if (rc) {
		ERR("%s:%d read back miscompare\n", __FILE__, __LINE__);
		goto out;
	}
	rc = memcmp(test, tmp + 0x800, 0x800);
	if (rc) {
		ERR("%s:%d read back miscompare\n", __FILE__, __LINE__);
		goto out;
	}

	/*
	 * Make sure we didn't corrupt other stuff, also make sure one
	 * blocklevel call will understand how to read from two windows
	 */
	for (i = 3; i < 10; i = i + 2) {
		rc = blocklevel_read(bl, i * 0x1000, tmp, 0x2000);
		if (rc) {
			ERR("blocklevel_read(0x%08x, 0x1000 failed with err: %d\n", i * 0x1000, rc);
			goto out;
		}
		rc = memcmp(((char *)test) + (i * 0x1000), tmp, 0x2000);
		if (rc) {
			ERR("%s:%d read back miscompare (pos: 0x%08x)\n", __FILE__, __LINE__, i * 0x1000);
			goto out;
		}
	}

	srand(1);
	/*
	 * Try to jump around the place doing a tonne of small reads.
	 * Worth doing the same with writes TODO
	 */
	for (i = 0; i < 1000; i++) {
		int r = rand();
		/* Avoid reading too far, just skip it */
		if ((r % 0x10000) + (r % 0x2000) > 0x10000)
			continue;

		rc = blocklevel_read(bl, 0x20000 + (r % 0x10000), tmp, r % 0x2000);
		if (rc) {
			ERR("blocklevel_read(0x%08x, 0x%08x) failed with err %d\n", 0x20000 + (r % 0x100000), r % 0x2000, rc);
			goto out;
		}
		rc = memcmp(((char *)test) + (r % 0x10000), tmp, r % 0x2000);
		if (rc) {
			ERR("%s:%d read back miscompare (pos: 0x%08x)\n", __FILE__, __LINE__, 0x20000 + (r % 0x10000));
			goto out;
		}
	}
out:
	free(tmp);
	return rc;
}

int main(void)
{
	struct blocklevel_device *bl;
	int rc;

	libflash_debug = true;

	mbox_server_init();

	printf("Doing mbox-flash V1 tests\n");

	/* run test */
	mbox_flash_init(&bl);
	rc = run_flash_test(bl);
	if (rc)
		goto out;
	/*
	 * Trick mbox-flash into thinking there was a reboot so we can
	 * switch to v2
	 */

	printf("Doing mbox-flash V2 tests\n");

	mbox_server_reset(2);

	/* Do all the tests again */
	rc = run_flash_test(bl);

out:
	mbox_flash_exit(bl);

	mbox_server_destroy();

	return rc;
}
