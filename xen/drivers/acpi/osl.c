/*
 *  acpi_osl.c - OS-dependent functions ($Revision: 83 $)
 *
 *  Copyright (C) 2000       Andrew Henroid
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 */
#include <asm/io.h>
#include <xen/config.h>
#include <xen/init.h>
#include <xen/pfn.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/acpi.h>
#include <xen/numa.h>
#include <acpi/acmacros.h>
#include <acpi/acpiosxf.h>
#include <acpi/platform/aclinux.h>
#include <xen/spinlock.h>
#include <xen/domain_page.h>
#include <xen/efi.h>
#include <xen/vmap.h>

#define _COMPONENT		ACPI_OS_SERVICES
ACPI_MODULE_NAME("osl")

#ifdef CONFIG_ACPI_CUSTOM_DSDT
#include CONFIG_ACPI_CUSTOM_DSDT_FILE
#endif

void __init acpi_os_printf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	acpi_os_vprintf(fmt, args);
	va_end(args);
}

void __init acpi_os_vprintf(const char *fmt, va_list args)
{
	static char buffer[512];

	vsnprintf(buffer, sizeof(buffer), fmt, args);

	printk("%s", buffer);
}

acpi_physical_address __init acpi_os_get_root_pointer(void)
{
       /* FIXME: The UEFI runtime support is not yet implimented.  
        * Hence the efi structure and efi_enabled variable initialized here.
        */
       const bool_t efi_enabled = 1;

       struct efi efi = {
              efi.mps    = 0x00000000,
              efi.acpi   = 0xFEBFA000,
              efi.acpi20 = 0xFEBFA014,
              efi.smbios = 0x00000000,
       };

	if (efi_enabled) {
	        printk("efi.mps    : 0x%08lx\n", efi.mps);
                printk("efi.acpi   : 0x%08lx\n", efi.acpi);
                printk("efi.acpi20 : 0x%08lx\n", efi.acpi20);
                printk("efi.smbios : 0x%08lx\n", efi.smbios);

		if (efi.acpi20 != EFI_INVALID_TABLE_ADDR)
			return efi.acpi20;
		else if (efi.acpi != EFI_INVALID_TABLE_ADDR)
			return efi.acpi;
		else {
			printk(KERN_ERR PREFIX
			       "System description tables not found\n");
			return 0;
		}
	} else {
		acpi_physical_address pa = 0;

		acpi_find_root_pointer(&pa);
		return pa;
	}
}

void __iomem *
acpi_os_map_memory(acpi_physical_address phys, acpi_size size)
{
	if (system_state >= SYS_STATE_active) {
		unsigned long pfn = PFN_DOWN(phys);
		unsigned int offs = phys & (PAGE_SIZE - 1);

		/* The low first Mb is always mapped. */
		if ( !((phys + size - 1) >> 20) )
			return __va(phys);
		return __vmap(&pfn, PFN_UP(offs + size), 1, 1, PAGE_HYPERVISOR_NOCACHE) + offs;
	}
#ifdef CONFIG_X86
	return __acpi_map_table(phys, size);
#else
	return __va(phys);
#endif
}

void acpi_os_unmap_memory(void __iomem * virt, acpi_size size)
{
	if (system_state >= SYS_STATE_active)
		vunmap((void *)((unsigned long)virt & PAGE_MASK));
}

#ifdef CONFIG_X86
acpi_status acpi_os_read_port(acpi_io_address port, u32 * value, u32 width)
{
	u32 dummy;

	if (!value)
		value = &dummy;

	*value = 0;
	if (width <= 8) {
		*(u8 *) value = inb(port);
	} else if (width <= 16) {
		*(u16 *) value = inw(port);
	} else if (width <= 32) {
		*(u32 *) value = inl(port);
	} else {
		BUG();
	}

	return AE_OK;
}

acpi_status acpi_os_write_port(acpi_io_address port, u32 value, u32 width)
{
	if (width <= 8) {
		outb(value, port);
	} else if (width <= 16) {
		outw(value, port);
	} else if (width <= 32) {
		outl(value, port);
	} else {
		BUG();
	}

	return AE_OK;
}
#endif

acpi_status
acpi_os_read_memory(acpi_physical_address phys_addr, u32 * value, u32 width)
{
	u32 dummy;
	void __iomem *virt_addr = acpi_os_map_memory(phys_addr, width >> 3);

	if (!value)
		value = &dummy;

	switch (width) {
	case 8:
		*(u8 *) value = readb(virt_addr);
		break;
	case 16:
		*(u16 *) value = readw(virt_addr);
		break;
	case 32:
		*(u32 *) value = readl(virt_addr);
		break;
	default:
		BUG();
	}

	acpi_os_unmap_memory(virt_addr, width >> 3);

	return AE_OK;
}

acpi_status
acpi_os_write_memory(acpi_physical_address phys_addr, u32 value, u32 width)
{
	void __iomem *virt_addr = acpi_os_map_memory(phys_addr, width >> 3);

	switch (width) {
	case 8:
		writeb(value, virt_addr);
		break;
	case 16:
		writew(value, virt_addr);
		break;
	case 32:
		writel(value, virt_addr);
		break;
	default:
		BUG();
	}

	acpi_os_unmap_memory(virt_addr, width >> 3);

	return AE_OK;
}

#ifdef CONFIG_X86
#define is_xmalloc_memory(ptr) ((unsigned long)(ptr) & (PAGE_SIZE - 1))
#else
#define is_xmalloc_memory(ptr) 1
#endif

void *__init acpi_os_alloc_memory(size_t sz)
{
	void *ptr;

	if (system_state == SYS_STATE_early_boot)
		return mfn_to_virt(alloc_boot_pages(PFN_UP(sz), 1));

	ptr = xmalloc_bytes(sz);
	ASSERT(!ptr || is_xmalloc_memory(ptr));
	return ptr;
}

void *__init acpi_os_zalloc_memory(size_t sz)
{
	void *ptr;

	if (system_state != SYS_STATE_early_boot) {
		ptr = xzalloc_bytes(sz);
		ASSERT(!ptr || is_xmalloc_memory(ptr));
		return ptr;
	}
	ptr = acpi_os_alloc_memory(sz);
	return ptr ? memset(ptr, 0, sz) : NULL;
}

void __init acpi_os_free_memory(void *ptr)
{
	if (is_xmalloc_memory(ptr))
		xfree(ptr);
	else if (ptr && system_state == SYS_STATE_early_boot)
		init_boot_pages(__pa(ptr), __pa(ptr) + PAGE_SIZE);
}
