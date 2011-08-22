/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#include <linux/kernel.h>	
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/highmem.h>

#include "ulccmod.h"
#define SUCCESS 0
#define DEVICE_NAME "ulccmod"
#define DEBUG

static int Device_Open = 0;

static int device_open(struct inode *inode, struct file *file)
{
#ifdef DEBUG
	printk(KERN_INFO "device_open(%p)\n", file);
#endif

	if (Device_Open)	/* JERRY: why only allow one caller to open the device? */
		return -EBUSY;

	Device_Open++;
	try_module_get(THIS_MODULE);
	return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file)
{
#ifdef DEBUG
	printk(KERN_INFO "device_release(%p,%p)\n", inode, file);
#endif

	/* 
	 * We're now ready for our next caller 
	 */
	Device_Open--;

	module_put(THIS_MODULE);
	return SUCCESS;
}

/* we don't support huge pages */
static unsigned long translate(struct mm_struct *mm, unsigned long address)
{
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep, pte;
        unsigned long page_address, pfn;

		page_address = address & PAGE_MASK;
        pgd = pgd_offset(mm, page_address);
        if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
                goto out;

        pud = pud_offset(pgd, page_address);
        if (pud_none(*pud) || unlikely(pud_bad(*pud)))
                goto out;

        pmd = pmd_offset(pud, page_address);
        if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
                goto out;

        ptep = pte_offset_map(pmd, page_address);
        if (!ptep)
                goto out;

        pte = *ptep;
        pte_unmap(ptep);
        if (pte_present(pte)) {
                pfn = pte_pfn(pte);
                if (pfn_valid(pfn)) {
                        return pfn;
                }
        }

out:
	return 0;
}

/* Both virtual page numbers and physical page numbers are in buffer.
 * To guarantee we have enough space for physical page numbers, buffer
 * should be filled with virtual page numbers first.
 */
static ssize_t
device_read(struct file *file, char __user * buffer, size_t length,
			loff_t * offset)
{
	unsigned long	address, pfn;
	unsigned long	fn, len;
	unsigned long	i;

#ifdef DEBUG
	printk(KERN_INFO "device_read %lu\n", length);
#endif

	copy_from_user(&fn, buffer, sizeof(unsigned long));

	if(fn)	/* compact format */
	{
		copy_from_user(&address, buffer + sizeof(unsigned long),
			sizeof(unsigned long));
		copy_from_user(&len, buffer + 2 * sizeof(unsigned long),
			sizeof(unsigned long));
		if(len * sizeof(unsigned long) > length)
		{
			return 0;
		}

		for(i = 0; i < len; i++)
		{
			pfn = translate(current->mm, address + i * 4096);
			copy_to_user(buffer + i * sizeof(unsigned long), &pfn,
				sizeof(unsigned long));
		}

		return len;
	}
	else	/* flexible format */
	{
		length -= sizeof(unsigned long);	/* remove the first unsigned long */
		for( i = 0; i < length; i += sizeof(unsigned long) ){
			copy_from_user(&address, buffer + sizeof(unsigned long) + i,
				sizeof(unsigned long));
			pfn = translate(current->mm, address);
			copy_to_user(buffer + i, &pfn, sizeof(unsigned long));
		}

		return length;
	}
}

/*
int device_ioctl(struct inode *inode,	
		 struct file *file,
		 unsigned int ioctl_num,
		 unsigned long ioctl_param)
{
	int i;
	char *temp;
	char ch;

	switch (ioctl_num) {
	case IOCTL_SET_MSG:
		temp = (char *)ioctl_param;

		get_user(ch, temp);
		for (i = 0; ch && i < BUF_LEN; i++, temp++)
			get_user(ch, temp);

		device_write(file, (char *)ioctl_param, i, 0);
		break;

	case IOCTL_GET_MSG:
		i = device_read(file, (char *)ioctl_param, 99, 0);
		put_user('\0', (char *)ioctl_param + i);
		break;

	case IOCTL_GET_NTH_BYTE:
		return Message[ioctl_param];
		break;
	}

	return SUCCESS;
}
*/

struct file_operations Fops = {
	.read = device_read,
/*	.ioctl = device_ioctl,*/
	.open = device_open,
	.release = device_release,
};

int init_module()
{
	int ret_val;

	ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &Fops);
	if (ret_val < 0) {
		printk(KERN_ALERT "Registering the character device failed with %d.", ret_val);
		return ret_val;
	}

	printk(KERN_INFO "Registeration is a success. The major device number is %d.\n",  MAJOR_NUM);
	printk(KERN_INFO "If you want to talk to the device driver, you'll have to create a device file. \n");
	printk(KERN_INFO "Suggest: mknod /tmp/%s c %d 0\n", DEVICE_FILE_NAME, MAJOR_NUM);

	return 0;
}

void cleanup_module()
{
	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
	printk(KERN_INFO "Module ulccmod is removed.\n");
}

MODULE_LICENSE("GPL");
