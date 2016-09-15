/* Copyright 2016 IBM Corp.
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

/* SPI Flash controller #1 (PNOR) */
#define SPI1_BASE	0x1E630000
#define SPI1_CONF	(SPI1_BASE + 0x00)
#define SPI1_CTRL	(SPI1_BASE + 0x04)
#define SPI1_ICTRL	(SPI1_BASE + 0x08)
#define SPI1_CE0_CTRL	(SPI1_BASE + 0x10)
#define SPI1_CE1_CTRL	(SPI1_BASE + 0x14)
#define SPI1_CE0_ADRR	(SPI1_BASE + 0x30)
#define SPI1_CE1_ADRR	(SPI1_BASE + 0x34)
#define SPI1_FREAD_TIMING	(SPI1_BASE + 0x94)
#define SPI1_FLASH_BASE		0x30000000

/* SPI Flash controller #2 (PNOR) */
#define SPI2_BASE	0x1E631000
#define SPI2_CONF	(SPI2_BASE + 0x00)
#define SPI2_CTRL	(SPI2_BASE + 0x04)
#define SPI2_ICTRL	(SPI1_BASE + 0x08)
#define SPI2_CE0_CTRL	(SPI2_BASE + 0x10)
#define SPI2_CE1_CTRL	(SPI2_BASE + 0x14)
#define SPI2_CE0_ADRR	(SPI2_BASE + 0x30)
#define SPI2_CE1_ADRR	(SPI2_BASE + 0x34)
#define SPI2_FREAD_TIMING	(SPI2_BASE + 0x94)
#define SPI2_FLASH_BASE		0x38000000

static int ast2500_sf_set_4b(struct spi_flash_ctrl *ctrl, bool enable)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);
	uint32_t reg = 0;

	if (ct->type != AST_SF_TYPE_PNOR)
		return enable ? FLASH_ERR_4B_NOT_SUPPORTED : 0;

	reg = ast_ahb_readl(SPI1_CTRL);

	if (enable)
		reg |= 1;
	else
		reg &= ~1;

	ct->mode_4b = enable;

	/* Update read mode */
	ast_ahb_writel(reg, SPI1_CTRL);

	return 0;
}

static bool ast2500_sf_init_pnor(struct ast_sf_ctrl *ct)
{
	uint32_t reg;

	ct->ctl_reg = SPI1_CE0_CTRL;
	ct->fread_timing_reg = SPI1_FREAD_TIMING;
	ct->flash = SPI1_FLASH_BASE;

	/* Enable writing to the controller */
	reg = ast_ahb_readl(SPI1_CONF);
	if (reg == 0xffffffff) {
		FL_ERR("AST_SF: Failed read from controller config\n");
		return false;
	}

	FL_DBG("Conf reg: 0x%08x\n", reg);

	/* Clear this reg incase it isn't */
	ast_ahb_writel(0, SPI1_ICTRL);

	ast_ahb_writel(reg | (1 << 16), SPI1_CONF);

	reg = ast_ahb_readl(SPI1_CTRL);
	if (reg & 1)
		ct->mode_4b = true;
	else
		ct->mode_4b = false;
	FL_DBG("CTRL reg: 0x%08x\n", reg);
	/*
	 * The defaults in this register are for flash timings to be div2.
	 * If flash seems slow, try clearing bit 8.
	 * It isn't clear what the default on the 2400 as it depends on
	 * hardware strapping
	 */
	//ast_ahb_writel(reg & ~(3 << 8), PNOR_SPI1_FCTL_CTRL);


	/* Set CE1 before CE0 incase an overlap causes a freakout */
	/* Start address of 0x34000000 (64M), the high is fixed */
	reg = ast_ahb_readl(SPI1_CE1_ADRR);
	FL_DBG("Setting up mapping 0x%x to 0x%x init: 0x%08x\n", 8 << 16, SPI1_CE1_ADRR, reg);
	ast_ahb_writel(8 << 16, SPI1_CE1_ADRR);
	/* High address of 0x34000000 (64M), the low is fixed */
	reg = ast_ahb_readl(SPI1_CE0_ADRR);
	FL_DBG("Setting up mapping 0x%x to 0x%x init: 0x%08x\n", 8 << 24, SPI1_CE0_ADRR, reg);
	ast_ahb_writel(8 << 24, SPI1_CE0_ADRR);

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

	/* Initial read mode is default */
	ct->ctl_read_val = ct->ctl_val;

	FL_DBG("CE0 CTRL 0x%08x\n", ct->ctl_val);

	ct->ctl_val &= ~(0xf << 24); /* Clear out and CE inactive pulse width */
	ct->ctl_val &= ~(0xf << 8); /* Clear out any HCLK value */
	ct->ctl_val =
		(0x00 << 28) | /* Single bit */
		(0x00 << 24) | /* CE# width 16T */
		(0x00 << 16) | /* no command */
		(0x04 <<  8) | /* HCLK/8 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);	       /* normal read */

	/* Initial read timings all 0 */
	ct->fread_timing_val = 0;

	/* Configure for read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
	ast_ahb_writel(ct->fread_timing_val, ct->fread_timing_reg);
	//reg = ast_ahb_readl(ct->fread_timing_reg);
	return true;
}

int ast2500_sf_open(uint8_t type, struct ast_sf_ctrl *ct)
{
	/*
	 * Memboot shouldn't be done here so we'll never handle
	 * AST_SF_TYPE_MEM
	 * This code isn't ready for AST_SF_TYPE_BMC but this may have to
	 * change
	 */
	if (type != AST_SF_TYPE_PNOR)
		return -EINVAL;

	ct->ops.set_4b = ast2500_sf_set_4b;
	if (!ast2500_sf_init_pnor(ct))
		return -EIO;

	FL_DBG("AST2500 init done\n");
	return 0;
}

void ast2500_sf_close(struct spi_flash_ctrl *ctrl)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);

	/* Restore control reg to read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	/* Additional cleanup */
	/* TODO Check with 2400 */

	/* Free the whole lot */
	free(ct);
}
