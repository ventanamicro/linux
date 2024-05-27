// SPDX-License-Identifier: GPL-2.0-only
/*
 * RISC-V Message Proxy (MPXY) Helper functions
 *
 * Copyright (C) 2024 Ventana Micro Systems Inc.
 */

#define pr_fmt(fmt) "riscv-mpxy: " fmt

#include <linux/jump_label.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <asm/sbi.h>

/* Per hart mpxy context */
struct sbi_mpxy {
	/* Shared memory base address */
	void *shmem;
	/* Shared memory physical address */
	phys_addr_t shmem_phys_addr;
	bool active;
};

/* Channel IDs data shared memory layout */
struct sbi_mpxy_channelids_data {
	/* remaining number of channel ids */
	u32 remaining;
	/* returned channel ids in current
	 function call */
	u32 returned;
	/* pointer to shared memory offset
	storing channel ids */
	u32 channel_array[];
};

DEFINE_PER_CPU(struct sbi_mpxy, sbi_mpxy);
DEFINE_STATIC_KEY_FALSE(sbi_mpxy_available);

#define sbi_mpxy_available() \
	static_branch_unlikely(&sbi_mpxy_available)

static int sbi_mpxy_exit(unsigned int cpu)
{
	struct sbiret sret;
	struct sbi_mpxy *mpxy;

	if (!sbi_mpxy_available())
		return -ENODEV;

	mpxy = per_cpu_ptr(&sbi_mpxy, cpu);
	if (!mpxy->shmem)
		return -ENOMEM;

	free_pages((unsigned long)mpxy->shmem, get_order(PAGE_SIZE));

	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SET_SHMEM,
			 0, -1U, -1U, 0, 0, 0);

	if (sret.error) {
		pr_err("Shared memory disabling failed for cpu-%d\n", cpu);
		return sbi_err_map_linux_errno(sret.error);
	}

	pr_info("Shared memory disabled for cpu-%d\n", cpu);

	mpxy->shmem = NULL;
	mpxy->shmem_phys_addr = 0;
	mpxy->active = false;

	return 0;
}

/**
 * Setup shared memory for a CPU, For linux clients
 * this function will automatically be called by the
 * MPXY interface to setup per cpu shared memory.
 * For non-linux clients(eg EFI runtime) separate
 * MPXY SBI function needs to be called.
 */
static int __sbi_mpxy_setup_shmem(unsigned int cpu)
{
	struct sbiret sret;
	struct page *shmem_page;
	struct sbi_mpxy *mpxy;

	if (!sbi_mpxy_available())
		return -ENODEV;

	mpxy = per_cpu_ptr(&sbi_mpxy, cpu);
	if (mpxy->active)
		return -EINVAL;

	shmem_page = alloc_pages(GFP_KERNEL | __GFP_ZERO,
				 get_order(PAGE_SIZE));
	if (!shmem_page) {
		sbi_mpxy_exit(cpu);
		pr_err("Shared memory setup failed for cpu-%d\n", cpu);
		return -ENOMEM;
	}
	mpxy->shmem = page_to_virt(shmem_page);
	mpxy->shmem_phys_addr = page_to_phys(shmem_page);

	/**
	 * Linux setup of shmem is done in mpxy OVERWRITE mode.
	 * flags[1:0] = 00b
	 **/
	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SET_SHMEM,
			 PAGE_SIZE, mpxy->shmem_phys_addr, 0, 0, 0, 0);
	if (sret.error) {
		sbi_mpxy_exit(cpu);
		return sbi_err_map_linux_errno(sret.error);
	}

	mpxy->active = true;

	return 0;
}

int sbi_mpxy_get_num_channels(u32 *channels_count)
{
	struct sbiret sret;
	u32 remaining, returned, start_index = 0;
	struct sbi_mpxy *mpxy = this_cpu_ptr(&sbi_mpxy);
	struct sbi_mpxy_channelids_data *sdata = mpxy->shmem;

	if (!sbi_mpxy_available() || !mpxy->active)
		return -ENODEV;

	if (!channels_count)
		return -EINVAL;

	get_cpu();
	/* get the remaining and returned fields to get the total */
	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_CHANNEL_IDS,
			 start_index, 0, 0, 0, 0, 0);

	if (!sret.error) {
		remaining = le32_to_cpu(sdata->remaining);
		returned =  le32_to_cpu(sdata->returned);
		*channels_count = remaining + returned;
	}

	put_cpu();

	return sbi_err_map_linux_errno(sret.error);
}

int sbi_mpxy_get_channel_ids(u32 *cbuf, unsigned long cbufsize)
{
	int rc;
	struct sbiret sret;
	u32 count, remaining, returned, sidx, start_index = 0, cidx = 0;
	struct sbi_mpxy *mpxy = this_cpu_ptr(&sbi_mpxy);
	struct sbi_mpxy_channelids_data *sdata = mpxy->shmem;

	if (!sbi_mpxy_available() || !mpxy->active)
		return -ENODEV;

	if (!cbuf)
		return -EINVAL;

	rc = sbi_mpxy_get_num_channels(&count);
	if (rc)
		return rc;

	/* Is passed buffer size(bytes) sufficient to store all
	 * available channel ids */
	if (!count || cbufsize < (count * sizeof(u32)))
		return -EINVAL;

	get_cpu();

	do {
		sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_CHANNEL_IDS,
			start_index, 0, 0, 0, 0, 0);
		if (sret.error)
			goto done;

		remaining = le32_to_cpu(sdata->remaining);
		returned =  le32_to_cpu(sdata->returned);

		for (sidx = 0; sidx < returned && cidx < count; sidx++) {
			cbuf[cidx] = le32_to_cpu(sdata->channel_array[sidx]);
			cidx += 1;
		}

		start_index = cidx;

	} while(remaining);

done:
	put_cpu();
	return sbi_err_map_linux_errno(sret.error);
}

int sbi_mpxy_read_attrs(u32 channelid, u32 base_attrid, u32 attr_count,
			void *attrs_buf)
{
	struct sbiret sret;
	struct sbi_mpxy *mpxy = this_cpu_ptr(&sbi_mpxy);

	if (!sbi_mpxy_available() || !mpxy->active)
		return -ENODEV;

	if (!attr_count || !attrs_buf)
		return -EINVAL;

	get_cpu();
	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_READ_ATTRS,
			 channelid, base_attrid, attr_count, 0, 0, 0);
	if (!sret.error) {
		memcpy(attrs_buf, mpxy->shmem, attr_count * sizeof(u32));
	}
	put_cpu();

	return sbi_err_map_linux_errno(sret.error);
}

int sbi_mpxy_write_attrs(u32 channelid, u32 base_attrid, u32 attr_count,
			void *attrs_buf)
{
	struct sbiret sret;
	struct sbi_mpxy *mpxy = this_cpu_ptr(&sbi_mpxy);

	if (!sbi_mpxy_available() || !mpxy->active)
		return -ENODEV;

	if (!attr_count || !attrs_buf)
		return -EINVAL;

	get_cpu();
	memcpy(mpxy->shmem, attrs_buf, attr_count * sizeof(u32));

	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_WRITE_ATTRS,
			 channelid, base_attrid, attr_count, 0, 0, 0);
	put_cpu();

	return sbi_err_map_linux_errno(sret.error);
}

int sbi_mpxy_send_message_withresp(u32 channelid, u32 msgid,
				   void *tx, unsigned long tx_msglen,
				   void *rx, unsigned long *rx_msglen)
{
	struct sbiret sret;
	struct sbi_mpxy *mpxy = this_cpu_ptr(&sbi_mpxy);

	if (!sbi_mpxy_available() || !mpxy->active)
		return -ENODEV;

	get_cpu();
	/**
	 * Message protocols allowed to have no data in
	 * messages
	 */
	if (tx_msglen)
		memcpy(mpxy->shmem, tx, tx_msglen);

	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITH_RESP,
			 channelid, msgid, tx_msglen, 0, 0, 0);

	if (rx && !sret.error) {
		memcpy(rx, mpxy->shmem, sret.value);
		if (rx_msglen)
			*rx_msglen = sret.value;
	}

	put_cpu();

	return sbi_err_map_linux_errno(sret.error);
}

int sbi_mpxy_send_message_noresp(u32 channelid, u32 msgid,
				 void *tx, unsigned long tx_msglen)
{
	struct sbiret sret;
	struct sbi_mpxy *mpxy = this_cpu_ptr(&sbi_mpxy);

	if (!sbi_mpxy_available() || !mpxy->active)
		return -ENODEV;

	get_cpu();
	/**
	 * Message protocols allowed to have no data in
	 * messages.
	 */
	if (tx_msglen)
		memcpy(mpxy->shmem, tx, tx_msglen);

	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_NO_RESP,
			 channelid, msgid, tx_msglen, 0, 0, 0);

	put_cpu();

	return sbi_err_map_linux_errno(sret.error);
}

int sbi_mpxy_get_notifications(u32 channelid, void *rx,
			       unsigned long *rx_msglen)
{
	struct sbiret sret;
	struct sbi_mpxy *mpxy = this_cpu_ptr(&sbi_mpxy);

	if (!sbi_mpxy_available() || !mpxy->active)
		return -ENODEV;

	if (!rx)
		return -EINVAL;

	get_cpu();
	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_NOTIFICATION_EVENTS,
			 channelid, 0, 0, 0, 0, 0);
	if (!sret.error) {
		memcpy(rx, mpxy->shmem, sret.value);
		if (rx_msglen)
			*rx_msglen = sret.value;
	}
	put_cpu();

	return sbi_err_map_linux_errno(sret.error);
}

static int __init sbi_mpxy_init(void)
{
	if ((sbi_spec_version < sbi_mk_version(1, 0)) ||
		sbi_probe_extension(SBI_EXT_MPXY) <= 0) {
		pr_info("SBI MPXY extension missing\n");
		return -ENODEV;
	}

	static_branch_enable(&sbi_mpxy_available);
	pr_info("SBI MPXY extension detected\n");
	/*
	 * Setup CPUHP notifier to setup shared
	 * memory on all CPUs
	 */
	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			  "riscv/mpxy-sbi:cpu-shmem-init",
			  __sbi_mpxy_setup_shmem,
			  sbi_mpxy_exit);
	return 0;
}

arch_initcall(sbi_mpxy_init);
