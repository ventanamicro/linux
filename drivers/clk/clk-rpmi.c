// SPDX-License-Identifier: GPL-2.0
/*
 * RISC-V MPXY Based Clock Driver
 *
 * Copyright (C) 2024 Ventana Micro Systems Ltd.
 */

#define pr_fmt(fmt) "sbi-mpxy-clock: " fmt

#include <linux/io.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/clk-provider.h>
#include <asm/sbi.h>
#include <asm/rpmi.h>

#define ATTR_COUNT(t, f)	(t - f + 1)

#define SBI_MPXY_CLK_MAX_NUM_RATES	16
#define SBI_MPXY_CLK_NAME_LEN		16

#define GET_RATE_LO_U32(rate_u64)	((u32)rate_u64)
#define GET_RATE_HI_U32(rate_u64)	((u32)((u64)(rate_u64) >> 32))
#define GET_RATE_U64(hi_u32, lo_u32)	((u64)hi_u32 << 32 | lo_u32)

#define to_mpxy_clk(clk) container_of(clk, struct sbi_mpxy_clk, hw)

enum sbi_mpxy_clock_config {
	SBI_MPXY_CLK_DISABLE = 0,
	SBI_MPXY_CLK_ENABLE = 1,
};

enum sbi_mpxy_clk_type {
	SBI_MPXY_CLK_DISCRETE = 0,
	SBI_MPXY_CLK_LINEAR = 1,
	SBI_MPXY_CLK_TYPE_MAX_IDX,
};

struct sbi_mpxy_clk_ctx {
	u32 channel_id;
	u32 max_msg_len;
	u32 msg_send_timeout;
};

static struct sbi_mpxy_clk_ctx mpxy_clk_ctx;

union rpmi_clk_rate {
	struct {
		u32 lo;
		u32 hi;
	} discrete[SBI_MPXY_CLK_MAX_NUM_RATES];
	struct {
		u32 min_lo;
		u32 min_hi;
		u32 max_lo;
		u32 max_hi;
		u32 step_lo;
		u32 step_hi;
	} linear;
};

union sbi_mpxy_clk_rates {
	u64 discrete[SBI_MPXY_CLK_MAX_NUM_RATES];
	struct {
		u64 min;
		u64 max;
		u64 step;
	} linear;
};

struct sbi_mpxy_clk {
	u32 id;
	u32 num_rates;
	u32 transition_latency;
	enum sbi_mpxy_clk_type type;
	union sbi_mpxy_clk_rates *rates;
	char name[SBI_MPXY_CLK_NAME_LEN];
	struct clk_hw hw;
};

struct rpmi_get_num_clocks_rx {
	s32 status;
	u32 num_clocks;
};

struct rpmi_get_attrs_tx {
	u32 clkid;
};

struct rpmi_get_attrs_rx {
	s32 status;
	u32 flags;
	u32 num_rates;
	u32 transition_latency;
	char name[SBI_MPXY_CLK_NAME_LEN];
};

struct rpmi_get_supp_rates_tx {
	u32 clkid;
	u32 clk_rate_idx;
};

struct rpmi_get_supp_rates_rx {
	u32 status;
	u32 flags;
	u32 remaining;
	u32 returned;
	union rpmi_clk_rate rates;
};

struct rpmi_get_rate_tx {
	u32 clkid;
};

struct rpmi_get_rate_rx {
	u32 status;
	u32 lo;
	u32 hi;
};

struct rpmi_set_rate_tx {
	u32 clkid;
	u32 flags;
	u32 lo;
	u32 hi;
};

struct rpmi_set_rate_rx {
	u32 status;
};

struct rpmi_set_config_tx {
	u32 clkid;
	u32 config;
};

struct rpmi_set_config_rx {
	u32 status;
};

static int rpmi_to_linux_error(int rpmi_error)
{
	switch(rpmi_error) {
	case RPMI_SUCCESS:
		return 0;
	case RPMI_ERROR_DENIED:
		return -EPERM;
	case RPMI_ERROR_BUSY:
		return -EBUSY;
	case RPMI_ERROR_HW_FAULT:
		return -EFAULT;
	case RPMI_ERROR_TIMEOUT:
		return -ETIMEDOUT;
	case RPMI_ERROR_COMMS:
		return -ECOMM;
	case RPMI_ERROR_ALREADY:
		return -EALREADY;
	case RPMI_ERROR_OUT_OF_RANGE:
	case RPMI_ERROR_OUT_OF_RESOURCE:
	case RPMI_ERROR_INVALID_PARAM:
		return -EINVAL;
	case RPMI_ERROR_EXTENSION:
	case RPMI_ERROR_NOT_FOUND:
	case RPMI_ERROR_NOT_SUPPORTED:
	case RPMI_ERROR_FAILED:
	default:
		return -EOPNOTSUPP;
	}
}

static int sbi_mpxy_clk_get_num_clocks(u32 channel_id)
{
	int ret;
	struct rpmi_get_num_clocks_rx rx;

	ret = sbi_mpxy_send_message_withresp(channel_id,
					RPMI_CLK_SRV_GET_SYSTEM_CLOCKS,
					NULL, 0, &rx, NULL);

	if (ret)
		return ret;

	/* RPMI message status code */
	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	return rx.num_clocks;
}

/**
 * Get the RPMI Clock Attributes.
 * These attributes belong to a particular clock(clkid)
 * which are different from the MPXY channel attributes.
 */
static int sbi_mpxy_clk_get_attrs(u32 clkid, struct sbi_mpxy_clk *mpxy_clk)
{
	int ret;
	u8 format;
	unsigned long rxmsg_len;
	struct rpmi_get_attrs_tx tx;
	struct rpmi_get_attrs_rx rx;
	u32 channel_id = mpxy_clk_ctx.channel_id;

	tx.clkid = cpu_to_le32(clkid);
	ret = sbi_mpxy_send_message_withresp(channel_id,
					RPMI_CLK_SRV_GET_ATTRIBUTES,
					&tx, sizeof(struct rpmi_get_attrs_tx),
					&rx, &rxmsg_len);
	if (ret)
		return ret;

	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	mpxy_clk->id = clkid;
	mpxy_clk->num_rates = rx.num_rates;
	mpxy_clk->transition_latency = rx.transition_latency;
	strscpy(mpxy_clk->name, rx.name, SBI_MPXY_CLK_NAME_LEN);

	format = rx.flags >> 30;
	if (format >= SBI_MPXY_CLK_TYPE_MAX_IDX)
		return -EINVAL;

	mpxy_clk->type = format;

	return 0;
}

static int sbi_mpxy_clk_get_supported_rates(u32 clkid,
					    struct sbi_mpxy_clk *mpxy_clk)
{
	int ret, rateidx, j;
	unsigned long rxmsg_len;
	size_t clk_rate_idx = 0;
	struct rpmi_get_supp_rates_tx tx;
	struct rpmi_get_supp_rates_rx rx;

	tx.clkid = cpu_to_le32(clkid);
	tx.clk_rate_idx = 0;

	ret = sbi_mpxy_send_message_withresp(mpxy_clk_ctx.channel_id,
					RPMI_CLK_SRV_GET_SUPPORTED_RATES,
					&tx,
					sizeof(struct rpmi_get_supp_rates_tx),
					&rx, &rxmsg_len);
	if (ret)
		return ret;

	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	if (!rx.returned)
		return -EINVAL;

	if (mpxy_clk->type == SBI_MPXY_CLK_DISCRETE) {
		for (rateidx = 0; rateidx < rx.returned; rateidx++) {
			mpxy_clk->rates->discrete[rateidx] =
				GET_RATE_U64(rx.rates.discrete[rateidx].hi,
					rx.rates.discrete[rateidx].lo);
		}

		if (rx.remaining) {
			while (rx.remaining) {
			clk_rate_idx += rx.returned;
			tx.clk_rate_idx = clk_rate_idx;

			ret = sbi_mpxy_send_message_withresp(
				mpxy_clk_ctx.channel_id,
				RPMI_CLK_SRV_GET_SUPPORTED_RATES,
				&tx, sizeof(struct rpmi_get_supp_rates_tx),
				&rx, &rxmsg_len);
			for (j = 0; rateidx < (clk_rate_idx + rx.returned) &&
				j < rx.returned; rateidx++, j++) {
					mpxy_clk->rates->discrete[rateidx] =
					GET_RATE_U64(rx.rates.discrete[j].hi,
						rx.rates.discrete[j].lo);
				}
			}
		}
	} else if (mpxy_clk->type == SBI_MPXY_CLK_LINEAR) {
		mpxy_clk->rates->linear.min =
				GET_RATE_U64(rx.rates.linear.min_hi,
					rx.rates.linear.min_lo);
		mpxy_clk->rates->linear.max =
				GET_RATE_U64(rx.rates.linear.max_hi,
					rx.rates.linear.max_lo);
		mpxy_clk->rates->linear.step =
				GET_RATE_U64(rx.rates.linear.step_hi,
					rx.rates.linear.step_lo);
	}

	return 0;
}

static unsigned long sbi_mpxy_clk_recalc_rate(struct clk_hw *hw,
                                              unsigned long parent_rate)
{
        int ret;
        unsigned long rxmsg_len;
        struct rpmi_get_rate_tx tx;
        struct rpmi_get_rate_rx rx;
        struct sbi_mpxy_clk *mpxy_clk = to_mpxy_clk(hw);

        tx.clkid = cpu_to_le32(mpxy_clk->id);

        ret = sbi_mpxy_send_message_withresp(mpxy_clk_ctx.channel_id,
					RPMI_CLK_SRV_GET_RATE,
					&tx, sizeof(struct rpmi_get_rate_tx),
					&rx, &rxmsg_len);
        if (ret)
                return ret;

        if (rx.status)
                return rx.status;

        return GET_RATE_U64(rx.hi, rx.lo);
}

static long sbi_mpxy_clk_round_rate(struct clk_hw *hw,
                                    unsigned long rate,
                                    unsigned long *parent_rate)
{
        u64 fmin, fmax, ftmp;
        struct sbi_mpxy_clk *mpxy_clk = to_mpxy_clk(hw);

        if (mpxy_clk->type == SBI_MPXY_CLK_DISCRETE)
                return rate;

        fmin = mpxy_clk->rates->linear.min;
        fmax = mpxy_clk->rates->linear.max;

        if (rate <= fmin)
                return fmin;
        else if (rate >=  fmax)
                return fmax;

        ftmp = rate - fmin;
        ftmp += mpxy_clk->rates->linear.step - 1;
        do_div(ftmp, mpxy_clk->rates->linear.step);

        return ftmp * mpxy_clk->rates->linear.step + fmin;
}

static int sbi_mpxy_clk_set_rate(struct clk_hw *hw, unsigned long rate,
				 unsigned long parent_rate)
{
	int ret;
	unsigned long rxmsg_len;
	struct rpmi_set_rate_tx tx;
	struct rpmi_set_rate_rx rx;

	struct sbi_mpxy_clk *mpxy_clk = to_mpxy_clk(hw);

	tx.clkid = cpu_to_le32(mpxy_clk->id);
	tx.lo = cpu_to_le32(GET_RATE_LO_U32(rate));
	tx.hi = cpu_to_le32(GET_RATE_HI_U32(rate));

	ret = sbi_mpxy_send_message_withresp(mpxy_clk_ctx.channel_id,
					RPMI_CLK_SRV_SET_RATE,
					&tx, sizeof(struct rpmi_set_rate_tx),
					&rx, &rxmsg_len);
	if (ret)
		return ret;

	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	return 0;
}

static int sbi_mpxy_clk_enable(struct clk_hw *hw)
{
	int ret;
	unsigned long rxmsg_len;
	struct rpmi_set_config_tx tx;
	struct rpmi_set_config_rx rx;
	struct sbi_mpxy_clk *mpxy_clk = to_mpxy_clk(hw);

	tx.config = cpu_to_le32(SBI_MPXY_CLK_ENABLE);
	tx.clkid = cpu_to_le32(mpxy_clk->id);

	ret = sbi_mpxy_send_message_withresp(mpxy_clk_ctx.channel_id,
					RPMI_CLK_SRV_SET_CONFIG,
					&tx, sizeof(struct rpmi_set_config_tx),
					&rx, &rxmsg_len);
	if (ret)
		return ret;

	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	return 0;
}

static void sbi_mpxy_clk_disable(struct clk_hw *hw)
{
	int ret;
	unsigned long rxmsg_len;
	struct rpmi_set_config_tx tx;
	struct rpmi_set_config_rx rx;
	struct sbi_mpxy_clk *mpxy_clk = to_mpxy_clk(hw);

	tx.config = cpu_to_le32(SBI_MPXY_CLK_DISABLE);
	tx.clkid = cpu_to_le32(mpxy_clk->id);

	ret = sbi_mpxy_send_message_withresp(mpxy_clk_ctx.channel_id,
					RPMI_CLK_SRV_SET_CONFIG,
					&tx, sizeof(struct rpmi_set_config_tx),
					&rx, &rxmsg_len);
	if (ret || rx.status)
		pr_err("Failed to disable clk-%u\n", mpxy_clk->id);
}

static const struct clk_ops sbi_mpxy_clk_ops = {
        .recalc_rate = sbi_mpxy_clk_recalc_rate,
        .round_rate = sbi_mpxy_clk_round_rate,
        .set_rate = sbi_mpxy_clk_set_rate,
        .prepare = sbi_mpxy_clk_enable,
        .unprepare = sbi_mpxy_clk_disable,
};

static struct clk_hw *sbi_mpxy_clk_enumerate(struct device *dev, u32 clkid)
{
	int ret;
	unsigned long min_rate, max_rate;
	struct clk_hw *clk_hw;
	struct sbi_mpxy_clk *mpxy_clk;
	struct clk_init_data init;
	union sbi_mpxy_clk_rates *rates;

	rates = devm_kzalloc(dev, sizeof(union sbi_mpxy_clk_rates), GFP_KERNEL);
	if (!rates)
		return ERR_PTR(-ENOMEM);

	mpxy_clk = devm_kzalloc(dev, sizeof(struct sbi_mpxy_clk), GFP_KERNEL);
	if (!mpxy_clk)
		return ERR_PTR(-ENOMEM);

	mpxy_clk->rates = rates;

	ret = sbi_mpxy_clk_get_attrs(clkid, mpxy_clk);
	if (ret) {
		dev_err(dev, "Failed to get clk-%u attributes\n", clkid);
		return ERR_PTR(ret);
	}

	ret = sbi_mpxy_clk_get_supported_rates(clkid, mpxy_clk);
	if (ret) {
		dev_err(dev, "Get supported rates failed for clk-%u, %d\n",
			clkid, ret);
		return ERR_PTR(ret);
	}

	init.flags = CLK_GET_RATE_NOCACHE;
	init.num_parents = 0;
	init.ops = &sbi_mpxy_clk_ops;
	init.name = mpxy_clk->name;
	clk_hw = &mpxy_clk->hw;
	clk_hw->init = &init;

	ret = devm_clk_hw_register(dev, clk_hw);
	if (ret) {
		dev_err(dev, "Unable to register clk-%u\n", clkid);
		return ERR_PTR(ret);
	}

	if (mpxy_clk->type == SBI_MPXY_CLK_DISCRETE) {
		min_rate = mpxy_clk->rates->discrete[0];
		max_rate = mpxy_clk->rates->discrete[mpxy_clk->num_rates -  1];
	} else {
		min_rate = mpxy_clk->rates->linear.min;
		max_rate = mpxy_clk->rates->linear.max;
	}

	clk_hw_set_rate_range(clk_hw, min_rate, max_rate);

	return NULL;
}

static int sbi_mpxy_clk_probe(struct platform_device *pdev)
{
	u32 *attr_buf;
	int ret, num_clocks, i;
	u32 channel_id, attr_count, version;
	struct clk_hw *hw_ptr;
	struct of_phandle_args args;
        struct clk_hw_onecell_data *clk_data;

	if ((sbi_spec_version < sbi_mk_version(1, 0)) ||
		sbi_probe_extension(SBI_EXT_MPXY) <= 0) {
		dev_err(&pdev->dev, "sbi mpxy extension not present\n");
		return -ENODEV;
	}

	ret = of_parse_phandle_with_args(pdev->dev.of_node,
					 "mboxes", "#mbox-cells", 0, &args);
	if (ret) {
		dev_err(&pdev->dev, "Missing mboxes phandle\n");
		return ret;
	}

	if (args.args_count < 1) {
		dev_err(&pdev->dev, "mboxes args missing channel-id\n");
		of_node_put(args.np);
		return -EINVAL;
	}

	channel_id = args.args[0];

	attr_count = ATTR_COUNT(SBI_MPXY_ATTR_MSG_SEND_TIMEOUT,
				SBI_MPXY_ATTR_MSG_PROT_ID);

	attr_buf = devm_kzalloc(&pdev->dev, sizeof(u32) * attr_count,
				GFP_KERNEL);
	if (!attr_buf)
		return -ENOMEM;

	/**
	 * Read MPXY channel attributes.
	 * Channel attributes are different from RPMI clock attributes
	 */
	ret = sbi_mpxy_read_attrs(channel_id, SBI_MPXY_ATTR_MSG_PROT_ID,
				  attr_count, attr_buf);
	if (ret == -ENOTSUPP) {
		dev_err(&pdev->dev, "%u mpxy channel not available\n",
			channel_id);
		return -EPROBE_DEFER;
	}

	if (ret) {
		dev_err(&pdev->dev, "channel-%u: read attributes - %d\n",
			channel_id, ret);
		return ret;
	}

	if (attr_buf[0] != SBI_MPXY_MSGPROTO_RPMI_ID) {
		dev_err(&pdev->dev,
			"channel-%u: msgproto id mismatch, expect:%u, found:%u\n",
			channel_id, SBI_MPXY_MSGPROTO_RPMI_ID, attr_buf[0]);
		return -EINVAL;
	}

	version = RPMI_MSGPROTO_VERSION(RPMI_MAJOR_VER, RPMI_MINOR_VER);
	if (attr_buf[1] != version) {
		dev_err(&pdev->dev,
			"channel-%u: msgproto version mismatch, expect:%u, found:%u\n",
			channel_id, version, attr_buf[1]);
		return -EINVAL;
	}

	mpxy_clk_ctx.channel_id = channel_id;
	mpxy_clk_ctx.max_msg_len = attr_buf[2];
	mpxy_clk_ctx.msg_send_timeout = attr_buf[3];

	ret = sbi_mpxy_read_attrs(channel_id, SBI_MPXY_ATTR_MSGPROTO_ATTR_START,
				  1, attr_buf);
	if (ret) {
		dev_err(&pdev->dev, "channel-%u: read attributes - %d\n",
			channel_id, ret);
		return ret;
	}

	if (attr_buf[0] != RPMI_SRVGRP_CLOCK) {
		dev_err(&pdev->dev,
		"channel-%u ServiceGroup match failed, expected %x, found %x\n",
		channel_id, RPMI_SRVGRP_CLOCK, attr_buf[0]);
		return -EINVAL;
	}

	num_clocks = sbi_mpxy_clk_get_num_clocks(channel_id);
	if (!num_clocks) {
		dev_err(&pdev->dev, "No clocks found\n");
		return -ENODEV;
	}

	clk_data = devm_kzalloc(&pdev->dev,
				struct_size(clk_data, hws, num_clocks),
				GFP_KERNEL);
	if (!clk_data)
		return -ENOMEM;

	clk_data->num = num_clocks;

	for (i = 0; i < clk_data->num; i++) {
		hw_ptr = sbi_mpxy_clk_enumerate(&pdev->dev, i);
		if (IS_ERR(hw_ptr))
			dev_err(&pdev->dev, "failed to register clk-%d\n", i);
		clk_data->hws[i] = hw_ptr;
	}

	ret = devm_of_clk_add_hw_provider(&pdev->dev, of_clk_hw_onecell_get,
					clk_data);

	u32 events = 1;
	ret = sbi_mpxy_write_attrs(channel_id,
				   SBI_MPXY_ATTR_EVENTS_STATE_CONTROL,
				   1, &events);

	return ret;
}

static const struct of_device_id sbi_mpxy_clk_of_match[] = {
	{ .compatible = "riscv,rpmi-clock" },
	{ },
}

MODULE_DEVICE_TABLE(of, sbi_mpxy_clk_of_match);
#define DRIVER_NAME	"clk-sbi-mpxy"

static struct platform_driver sbi_mpxy_clk_platdrv = {
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = sbi_mpxy_clk_of_match,
	},
	.probe = sbi_mpxy_clk_probe,
};

static int __init sbi_mpxy_clk_driver_init(void)
{
	int ret;

	ret = platform_driver_register(&sbi_mpxy_clk_platdrv);
	if(ret)
		platform_driver_unregister(&sbi_mpxy_clk_platdrv);

	return ret;
}

device_initcall(sbi_mpxy_clk_driver_init);

MODULE_AUTHOR("Rahul Pathak <rpathak@ventanamicro.com>");
MODULE_DESCRIPTION("Clock Driver based on SBI MPXY extension");
MODULE_LICENSE("GPL");
