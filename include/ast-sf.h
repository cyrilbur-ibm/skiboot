/* Copyright 2016 IBM Corp.
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
#ifndef __AST_SF_H
#define __AST_SF_H

#ifndef __unused
#define __unused __attribute__((unused))
#endif

struct ast_sf_ctrl {
	/* We have 2 controllers, one for the BMC flash, one for the PNOR */
	uint8_t			type;

	/* Address and previous value of the ctrl register */
	uint32_t		ctl_reg;

	/* Control register value for normal commands */
	uint32_t		ctl_val;

	/* Control register value for (fast) reads */
	uint32_t		ctl_read_val;

	/* Flash read timing register  */
	uint32_t		fread_timing_reg;
	uint32_t		fread_timing_val;

	/* Address of the flash mapping */
	uint32_t		flash;

	/* Current 4b mode */
	bool			mode_4b;

	/* Callbacks */
	struct spi_flash_ctrl	ops;
};

int ast2400_sf_open(uint8_t type, struct ast_sf_ctrl *ct);
int ast2500_sf_open(uint8_t type, struct ast_sf_ctrl *ct);

#endif /* __AST_SF_H */

