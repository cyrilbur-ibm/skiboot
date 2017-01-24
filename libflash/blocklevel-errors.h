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

#include <libflash/blocklevel.h>

#ifdef __SKIBOOT__
#include <opal-api.h>
static inline int check_rc(struct blocklevel_device *bl, int rc)
{
	if (!(bl->flags & OPAL_RETURN_CODE_ONLY) || rc < 1)
		return rc;

	switch (rc) {
		case FLASH_ERR_MALLOC_FAILED:
		return OPAL_NO_MEM;

		case FLASH_ERR_CHIP_UNKNOWN:
		return OPAL_HARDWARE;

		case FLASH_ERR_PARM_ERROR:
		return OPAL_PARAMETER;

		case FLASH_ERR_ERASE_BOUNDARY:
		return OPAL_UNSUPPORTED; /* or just OPAL_PARAMETER? */

		case FLASH_ERR_WREN_TIMEOUT:
		case FLASH_ERR_WIP_TIMEOUT:
		case FLASH_ERR_VERIFY_FAILURE:
		return OPAL_INTERNAL_ERROR;

		case FLASH_ERR_4B_NOT_SUPPORTED:
		return OPAL_UNSUPPORTED;

		case FLASH_ERR_CTRL_CONFIG_MISMATCH:
		return OPAL_INTERNAL_ERROR;

		case FLASH_ERR_CHIP_ER_NOT_SUPPORTED:
		case FLASH_ERR_CTRL_CMD_UNSUPPORTED:
		return OPAL_UNSUPPORTED;

		case FLASH_ERR_CTRL_TIMEOUT:
		case FLASH_ERR_ECC_INVALID:
		case FLASH_ERR_BAD_READ:
		return OPAL_INTERNAL_ERROR;
	}

	return rc;
}
#else
static inline int check_rc(struct blocklevel_device *bl __attribute__((unused)), int rc)
{
	return rc;
}
#endif
