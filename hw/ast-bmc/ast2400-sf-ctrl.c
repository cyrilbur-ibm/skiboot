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
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <libflash/libflash.h>
#include <libflash/libflash-priv.h>

#include "ast.h"
#include "ast-sf.h"

/* SPI Flash controller #1 (BMC) */
#define BMC_SPI_FCTL_BASE	0x1E620000
#define BMC_SPI_FCTL_CE_CTRL	(BMC_SPI_FCTL_BASE + 0x04)
#define BMC_SPI_FCTL_CTRL	(BMC_SPI_FCTL_BASE + 0x10)
#define BMC_SPI_FREAD_TIMING	(BMC_SPI_FCTL_BASE + 0x94)
#define BMC_FLASH_BASE		0x20000000

/* SPI Flash controller #2 (PNOR) */
#define PNOR_SPI_FCTL_BASE	0x1E630000
#define PNOR_SPI_FCTL_CONF	(PNOR_SPI_FCTL_BASE + 0x00)
#define PNOR_SPI_FCTL_CTRL	(PNOR_SPI_FCTL_BASE + 0x04)
#define PNOR_SPI_FREAD_TIMING	(PNOR_SPI_FCTL_BASE + 0x14)
#define PNOR_FLASH_BASE		0x30000000

static bool ast2400_sf_init_pnor(struct ast_sf_ctrl *ct)
{
	uint32_t reg;

	ct->ctl_reg = PNOR_SPI_FCTL_CTRL;
	ct->fread_timing_reg = PNOR_SPI_FREAD_TIMING;
	ct->flash = PNOR_FLASH_BASE;

	/* Enable writing to the controller */
	reg = ast_ahb_readl(PNOR_SPI_FCTL_CONF);
	if (reg == 0xffffffff) {
		FL_ERR("AST_SF: Failed read from controller config\n");
		return false;
	}
	ast_ahb_writel(reg | 1, PNOR_SPI_FCTL_CONF);

	/*
	 * Snapshot control reg and sanitize it for our
	 * use, switching to 1-bit mode, clearing user
	 * mode if set, etc...
	 *
	 * Also configure SPI clock to something safe
	 * like HCLK/8 (24Mhz)
	 */
	ct->ctl_val = ast_ahb_readl(ct->ctl_reg);
	if (ct->ctl_val == 0xffffffff) {
		FL_ERR("AST_SF: Failed read from controller control\n");
		return false;
	}

	ct->ctl_val = (ct->ctl_val & 0x2000) |
		(0x00 << 28) | /* Single bit */
		(0x00 << 24) | /* CE# width 16T */
		(0x00 << 16) | /* no command */
		(0x04 <<  8) | /* HCLK/8 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);	       /* normal read */

	/* Initial read mode is default */
	ct->ctl_read_val = ct->ctl_val;

	/* Initial read timings all 0 */
	ct->fread_timing_val = 0;

	/* Configure for read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
	ast_ahb_writel(ct->fread_timing_val, ct->fread_timing_reg);

	if (ct->ctl_val & 0x2000)
		ct->mode_4b = true;
	else
		ct->mode_4b = false;

	return true;
}

static bool ast2400_sf_init_bmc(struct ast_sf_ctrl *ct)
{
	ct->ctl_reg = BMC_SPI_FCTL_CTRL;
	ct->fread_timing_reg = BMC_SPI_FREAD_TIMING;
	ct->flash = BMC_FLASH_BASE;

	/*
	 * Snapshot control reg and sanitize it for our
	 * use, switching to 1-bit mode, clearing user
	 * mode if set, etc...
	 *
	 * Also configure SPI clock to something safe
	 * like HCLK/8 (24Mhz)
	 */
	ct->ctl_val =
		(0x00 << 28) | /* Single bit */
		(0x00 << 24) | /* CE# width 16T */
		(0x00 << 16) | /* no command */
		(0x04 <<  8) | /* HCLK/8 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);	       /* normal read */

	/* Initial read mode is default */
	ct->ctl_read_val = ct->ctl_val;

	/* Initial read timings all 0 */
	ct->fread_timing_val = 0;

	/* Configure for read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
	ast_ahb_writel(ct->fread_timing_val, ct->fread_timing_reg);

	ct->mode_4b = false;

	return true;
}

static int ast2400_sf_set_4b(struct spi_flash_ctrl *ctrl, bool enable)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);
	uint32_t ce_ctrl = 0;

	if (ct->type == AST_SF_TYPE_BMC && ct->ops.finfo->size > 0x1000000)
		ce_ctrl = ast_ahb_readl(BMC_SPI_FCTL_CE_CTRL);
	else if (ct->type != AST_SF_TYPE_PNOR)
		return enable ? FLASH_ERR_4B_NOT_SUPPORTED : 0;

	/*
	 * We update the "old" value as well since when quitting
	 * we don't restore the mode of the flash itself so we need
	 * to leave the controller in a compatible setup
	 */
	if (enable) {
		ct->ctl_val |= 0x2000;
		ct->ctl_read_val |= 0x2000;
		ce_ctrl |= 0x1;
	} else {
		ct->ctl_val &= ~0x2000;
		ct->ctl_read_val &= ~0x2000;
		ce_ctrl &= ~0x1;
	}
	ct->mode_4b = enable;

	/* Update read mode */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	if (ce_ctrl && ct->type == AST_SF_TYPE_BMC)
		ast_ahb_writel(ce_ctrl, BMC_SPI_FCTL_CE_CTRL);

	return 0;
}

int ast2400_sf_open(uint8_t type, struct ast_sf_ctrl *ct)
{
	if (type != AST_SF_TYPE_PNOR && type != AST_SF_TYPE_BMC
	    && type != AST_SF_TYPE_MEM)
		return -EINVAL;

	if (type == AST_SF_TYPE_BMC)
		ct->ops.set_4b = ast2400_sf_set_4b;

	if (type == AST_SF_TYPE_PNOR) {
		if (!ast2400_sf_init_pnor(ct))
			return -EIO;
	} else if (type == AST_SF_TYPE_BMC) {
		if (!ast2400_sf_init_bmc(ct))
			return -EIO;
	}

	return 0;
}

void ast2400_sf_close(struct spi_flash_ctrl *ctrl)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);

	/* Restore control reg to read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	/* Additional cleanup */
	if (ct->type == AST_SF_TYPE_PNOR) {
		uint32_t reg = ast_ahb_readl(PNOR_SPI_FCTL_CONF);
		if (reg != 0xffffffff)
			ast_ahb_writel(reg & ~1, PNOR_SPI_FCTL_CONF);
	}

	/* Free the whole lot */
	free(ct);
}
