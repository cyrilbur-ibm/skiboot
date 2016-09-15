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

static int ast2500_sf_setup(struct spi_flash_ctrl *ctrl, uint32_t *tsize)
{
	/*
	 * There is some setup we can do based on the size of the flash
	 * that libflash reports. Setup the SPI1 CE0 window correctly.
	 */

	(void) ctrl;

	if (tsize) {
		uint32_t regCE0;
		uint32_t size = *tsize;
		size = size >> 23; /* Get the number in MB (>> 20) and divide by 8 ( >> 3) */
		if (size == 16) {
			FL_DBG("128MB flash chip detected! Your maximum range is capped at 120MB\n");
			size--;
		} else if (size > 16) {
			FL_ERR("Greater than 128MB flash chip detected, don't do that, bailing\n");
			return 1;
		}

		regCE0 = ast_ahb_readl(SPI1_CE0_ADRR);
		/*
		 * Avoid (temporary) overlap incase it causes a freakout.
		 * If the high address of CE0 is less than size, change CE1
		 * first. Otherwise change CE0 first.
		 */
		FL_DBG("Setting up mapping 0x%x bits 27-24 of CE0 for a high address equal to %dMB\n", size, size << 3);
		FL_DBG("Setting up mapping 0x%x bits 19-16 if CE1 for an unmaped region %d-128MB\n", size, size << 3);
		if (((regCE0 >> 24) & 0xf) < size) {
			/* The high address of CE1 is fixed */
			ast_ahb_writel(size << 16, SPI1_CE1_ADRR);
			/* The low address of CE0 is fixed */
			ast_ahb_writel(size << 24, SPI1_CE0_ADRR);
		} else {
			/* The low address of CE0 is fixed */
			ast_ahb_writel(size << 24, SPI1_CE0_ADRR);
			/* The high address of CE1 is fixed */
			ast_ahb_writel(size << 16, SPI1_CE1_ADRR);
		}
		*tsize = size << 23; /* Incase of 128MB chip we will have changed it */
	}

	/* Do nothing else until we tune properly */
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
	return true;
}

int ast2500_sf_open(uint8_t type, struct spi_flash_ctrl **ctrl)
{
	struct ast_sf_ctrl *ct;
	int rc;

	/*
	 * Memboot shouldn't be done here so we'll never handle
	 * AST_SF_TYPE_MEM
	 * This code isn't ready for AST_SF_TYPE_BMC but this may have to
	 * change
	 */
	if (type != AST_SF_TYPE_PNOR)
		return -EINVAL;

	/* Generic init */
	rc = ast_sf_open(type, ctrl);
	if (rc)
		return rc;

	ct = container_of(*ctrl, struct ast_sf_ctrl, ops);
	ct->ops.set_4b = ast2500_sf_set_4b;
	ct->ops.setup = ast2500_sf_setup;
	if (!ast2500_sf_init_pnor(ct)) {
		free(ct);
		return -EIO;
	}

	return 0;
}

void ast2500_sf_close(struct spi_flash_ctrl *ctrl)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);

	/* Restore control reg */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	/*
	 * Additional cleanup, for the moment do nothing. Perhaps set the
	 * new ast2500 registers back to defaults
	 */

	/* Free the whole lot */
	free(ct);
}
