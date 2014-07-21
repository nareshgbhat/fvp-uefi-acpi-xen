#include <asm/efibind.h>
#include <efi/efidef.h>
#include <efi/efierr.h>
#include <efi/eficon.h>
#include <efi/efidevp.h>
#include <efi/eficapsule.h>
#include <efi/efiapi.h>
#include <xen/efi.h>
#include <xen/spinlock.h>
#include <asm/page.h>
#include <efi/efiprot.h>
#include <efi/efi-shared.h>
#include <public/xen.h>
#include <xen/compile.h>
#include <xen/ctype.h>
#include <xen/init.h>
#include <xen/keyhandler.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#if EFI_PAGE_SIZE != PAGE_SIZE
# error Cannot use xen/pfn.h here!
#endif
#include <xen/string.h>
#include <xen/stringify.h>
#include <xen/libfdt/libfdt.h>
#include <asm/setup.h>


void __init noreturn blexit(const CHAR16 *str);

#define DEVICE_TREE_GUID \
{0xb1b621d5, 0xf19c, 0x41a5, {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}}

extern CHAR16 __initdata newline[];
extern SIMPLE_TEXT_OUTPUT_INTERFACE *__initdata StdOut;
extern SIMPLE_TEXT_OUTPUT_INTERFACE *__initdata StdERR;
extern EFI_BOOT_SERVICES *__initdata efi_bs;


static EFI_HANDLE __initdata efi_ih;

static struct file __initdata cfg;
static struct file __initdata kernel;
static struct file __initdata ramdisk;
static struct file __initdata dtb;

static unsigned long mmap_size;
static EFI_MEMORY_DESCRIPTOR *mmap_ptr;

/*
 * Hacky way to make sure EFI allocations end up in memory that XEN
 * includes in its mappings.
 * RFRANZ_TODO - this needs to be resolved properly.
 */
static EFI_PHYSICAL_ADDRESS max_addr = 0xffffffff;

static void *new_fdt;

static EFI_STATUS __init efi_process_memory_map_bootinfo(EFI_MEMORY_DESCRIPTOR *map,
                                                unsigned long mmap_size,
                                                unsigned long desc_size)
{
    int Index;
    int i = 0;

    EFI_MEMORY_DESCRIPTOR *desc_ptr = map;

    for ( Index = 0; Index < (mmap_size / desc_size); Index++ )
    {
        if ( desc_ptr->Type == EfiConventionalMemory
             || desc_ptr->Type == EfiBootServicesCode
             || desc_ptr->Type == EfiBootServicesData )
        {
            bootinfo.mem.bank[i].start = desc_ptr->PhysicalStart;
            bootinfo.mem.bank[i].size = desc_ptr->NumberOfPages * EFI_PAGE_SIZE;
            if ( ++i >= NR_MEM_BANKS )
            {
                PrintStr(L"Warning: bootinfo mem banks exhausted\r\n");
                break;
            }
        }
        desc_ptr = NextMemoryDescriptor(desc_ptr, desc_size);
    }

    bootinfo.mem.nr_banks = i;
    return EFI_SUCCESS;

}

static EFI_STATUS __init efi_get_memory_map(EFI_SYSTEM_TABLE *sys_table_arg,
                                            EFI_MEMORY_DESCRIPTOR **map,
                                            unsigned long *mmap_size,
                                            unsigned long *desc_size,
                                            UINT32 *desc_ver,
                                            unsigned long *key_ptr)
{
    EFI_MEMORY_DESCRIPTOR *m = NULL;
    EFI_STATUS status;
    unsigned long key;
    u32 desc_version;

    *map = NULL;
    *mmap_size = EFI_PAGE_SIZE;
again:
    *mmap_size += EFI_PAGE_SIZE;  /* Page size is allocation granularity */
    status = sys_table_arg->BootServices->AllocatePool(EfiLoaderData,
                                                       *mmap_size, (void **)&m);
    if ( status != EFI_SUCCESS )
        return status;

    *desc_size = 0;
    key = 0;
    status = sys_table_arg->BootServices->GetMemoryMap(mmap_size, m, &key,
                                                       desc_size,
                                                       &desc_version);
    if ( status == EFI_BUFFER_TOO_SMALL )
    {
        sys_table_arg->BootServices->FreePool(m);
        goto again;
    }

    if ( status != EFI_SUCCESS )
    {
        sys_table_arg->BootServices->FreePool(m);
        return status;
    }

    if ( key_ptr && status == EFI_SUCCESS )
        *key_ptr = key;
    if ( desc_ver && status == EFI_SUCCESS )
        *desc_ver = desc_version;

    *map = m;
    return status;
}


static void __init *lookup_fdt_config_table(EFI_SYSTEM_TABLE *sys_table)
{
    const EFI_GUID fdt_guid = DEVICE_TREE_GUID;
    EFI_CONFIGURATION_TABLE *tables;
    void *fdt;
    int i;

    tables = sys_table->ConfigurationTable;
    fdt = NULL;

    for ( i = 0; i < sys_table->NumberOfTableEntries; i++ )
    {
        if ( match_guid(&tables[i].VendorGuid, &fdt_guid) )
        {
            fdt = tables[i].VendorTable;
            break;
        }
    }
    return fdt;
}

/*
 * Get (or set if not present) the #addr-cells and #size cells
 * properties of the chosen node.  We need to know these to
 * properly construct the address ranges used to describe the files
 * loaded by the stub.
 */
static int __init setup_chosen_node(void *fdt, int *addr_cells, int *size_cells)
{
    int node;
    const struct fdt_property *prop;
    int len;
    uint32_t val;

    if ( !fdt || !addr_cells || !size_cells )
        return -1;


    /* locate chosen node, which is where we add XEN module info. */
    node = fdt_subnode_offset(fdt, 0, "chosen");
    if ( node < 0 )
    {
        node = fdt_add_subnode(fdt, 0, "chosen");
        if ( node < 0 )
            return node;
    }

    /* Get or set #address-cells and #size-cells */
    prop = fdt_get_property(fdt, node, "#address-cells", &len);
    if ( !prop )
    {
        PrintStr(L"No #address-cells in chosen node, setting to 2\r\n");
        val = cpu_to_fdt32(2);
        if ( fdt_setprop(fdt, node, "#address-cells", &val, sizeof(val)) )
            return -1;
        *addr_cells = 2;
    }
    else
        *addr_cells = fdt32_to_cpu(*((uint32_t *)prop->data));

    prop = fdt_get_property(fdt, node, "#size-cells", &len);
    if ( !prop )
    {
        PrintStr(L"No #size-cells in chosen node, setting to 2\r\n");
        val = cpu_to_fdt32(2);
        if ( fdt_setprop(fdt, node, "#size-cells", &val, sizeof(val)) )
            return -1;
        *size_cells = 2;
    }
    else
        *size_cells = fdt32_to_cpu(*((uint32_t *)prop->data));

    /*
     * Make sure ranges is empty if it exists, otherwise create empty ranges
     * property.
     */
    prop = fdt_get_property(fdt, node, "ranges", &len);
    if ( !prop )
    {
        PrintStr(L"No ranges in chosen node, creating empty\r\n");
        val = cpu_to_fdt32(2);
        if ( fdt_setprop(fdt, node, "#size-cells", &val, 0) )
            return -1;
    }
    else
    {
        if ( fdt32_to_cpu(prop->len) )
        {
            PrintStr(L"Non-empty ranges in chosen node, aborting\r\n");
            return -1;
        }
    }
    return node;
}


/*
 * Set a single 'reg' property taking into account the
 * configured addr and size cell sizes.
 */
static int __init fdt_set_reg(void *fdt, int node, int addr_cells,
                              int size_cells, uint64_t addr, uint64_t len)
{
    uint8_t data[16]; /* at most 2 64 bit words */
    void *p = data;

    /* Make sure that the values provided can be represented in
     * the reg property.
     */
    if ( addr_cells == 1 && (addr >> 32) )
        return -1;
    if ( size_cells == 1 && (len >> 32) )
        return -1;

    if ( addr_cells == 1 )
    {
        *(uint32_t *)p = cpu_to_fdt32(addr);
        p += sizeof(uint32_t);
    }
    else if ( addr_cells == 2 )
    {
        *(uint64_t *)p = cpu_to_fdt64(addr);
        p += sizeof(uint64_t);
    }
    else
        return -1;


    if ( size_cells == 1 )
    {
        *(uint32_t *)p = cpu_to_fdt32(len);
        p += sizeof(uint32_t);
    }
    else if ( size_cells == 2 )
    {
        *(uint64_t *)p = cpu_to_fdt64(len);
        p += sizeof(uint64_t);
    }
    else
        return -1;

    return(fdt_setprop(fdt, node, "reg", data, p - (void *)data));
}

/*
 * Add the FDT nodes for the standard EFI information, which consist
 * of the System table address, the address of the final EFI memory map,
 * and memory map information.
 */
static EFI_STATUS __init fdt_add_uefi_nodes(EFI_SYSTEM_TABLE *sys_table,
                                            void *fdt,
                                            EFI_MEMORY_DESCRIPTOR *memory_map,
                                            unsigned long map_size,
                                            unsigned long desc_size,
                                            u32 desc_ver)
{
    int node;
    int status;
    u32 fdt_val32;
    u64 fdt_val64;
    int prev;
    /*
     * Delete any memory nodes present.  The EFI memory map is the only
     * memory description provided to XEN.
     */
    prev = 0;
    for (;;)
    {
        const char *type;
        int len;

        node = fdt_next_node(fdt, prev, NULL);
        if ( node < 0 )
            break;

        type = fdt_getprop(fdt, node, "device_type", &len);
        if ( type && strncmp(type, "memory", len) == 0 )
        {
            fdt_del_node(fdt, node);
            continue;
        }

        prev = node;
    }

    /* Add FDT entries for EFI runtime services in chosen node. */
    node = fdt_subnode_offset(fdt, 0, "chosen");
    if ( node < 0 )
    {
        node = fdt_add_subnode(fdt, 0, "chosen");
        if ( node < 0 )
        {
            status = node; /* node is error code when negative */
            goto fdt_set_fail;
        }
    }

    fdt_val64 = cpu_to_fdt64((u64)(unsigned long)sys_table);
    status = fdt_setprop(fdt, node, "linux,uefi-system-table",
                         &fdt_val64, sizeof(fdt_val64));
    if ( status )
        goto fdt_set_fail;

    fdt_val64 = cpu_to_fdt64((u64)(unsigned long)memory_map);
    status = fdt_setprop(fdt, node, "linux,uefi-mmap-start",
                         &fdt_val64,  sizeof(fdt_val64));
    if ( status )
        goto fdt_set_fail;

    fdt_val32 = cpu_to_fdt32(map_size);
    status = fdt_setprop(fdt, node, "linux,uefi-mmap-size",
                         &fdt_val32,  sizeof(fdt_val32));
    if ( status )
        goto fdt_set_fail;

    fdt_val32 = cpu_to_fdt32(desc_size);
    status = fdt_setprop(fdt, node, "linux,uefi-mmap-desc-size",
                         &fdt_val32, sizeof(fdt_val32));
    if ( status )
        goto fdt_set_fail;

    fdt_val32 = cpu_to_fdt32(desc_ver);
    status = fdt_setprop(fdt, node, "linux,uefi-mmap-desc-ver",
                         &fdt_val32, sizeof(fdt_val32));
    if ( status )
        goto fdt_set_fail;

    return EFI_SUCCESS;

fdt_set_fail:
    if ( status == -FDT_ERR_NOSPACE )
        return EFI_BUFFER_TOO_SMALL;

    return EFI_LOAD_ERROR;
}



/*
 * Allocates new memory for a larger FDT, and frees existing memory if
 * struct file size is non-zero.  Updates file struct with new memory
 * address/size for later freeing.  If fdtfile.ptr is NULL, an empty FDT
 * is created.
 */
static void __init *fdt_increase_size(struct file *fdtfile, int add_size)
{
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS fdt_addr;
    int fdt_size;
    int pages;
    void *new_fdt;


    if ( fdtfile->ptr )
        fdt_size = fdt_totalsize(fdtfile->ptr);
    else
        fdt_size = 0;

    pages = PFN_UP(fdt_size) + PFN_UP(add_size);
    fdt_addr = max_addr;
    status = efi_bs->AllocatePages(AllocateMaxAddress, EfiLoaderData,
                                   pages, &fdt_addr);

    if ( status != EFI_SUCCESS )
        return NULL;

    new_fdt = (void *)fdt_addr;

    if ( fdt_size )
    {
        if ( fdt_open_into(dtb.ptr, new_fdt, pages * EFI_PAGE_SIZE) )
            return NULL;
    }
    else
    {
        /*
         * Create an empty FDT if not provided one, which is the expected case
         * when booted from the UEFI shell on an ACPI only system.  We will use
         * the FDT to pass the EFI information to XEN, as well as nodes for
         * any modules the stub loads.  The ACPI tables are part of the UEFI
         * system table that is passed in the FDT.
         */
        PrintStr(L"before fdt_create_empty_tree\r\n");
        if ( fdt_create_empty_tree(new_fdt, pages * EFI_PAGE_SIZE) )
            return NULL;
    }

    /*
     * Now that we have the new FDT allocated and copied, free the
     * original and update the struct file so that the error handling
     * code will free it.  If the original FDT came from a configuration
     * table, we don't own that memory and can't free it.
     */
    if ( dtb.size )
        efi_bs->FreePages(dtb.addr, PFN_UP(dtb.size));

    /* Update 'file' info for new memory so we clean it up on error exits */
    dtb.addr = fdt_addr;
    dtb.size = pages * EFI_PAGE_SIZE;
    return new_fdt;
}


/*
 * Allocate a new FDT with enough space for EFI and XEN related updates,
 * populating with content from a FDT specified in the configuration file
 * or configuration table if present.  If neither is available, create an
 * empty FDT.
 */
static void __init *create_new_fdt(EFI_SYSTEM_TABLE *SystemTable,
                                   EFI_FILE_HANDLE dir_handle, struct file *cfgfile,
                                   const char *section)
{
    union string name = { NULL };

    /* load dtb from config file or configuration table */
    name.s = get_value(cfgfile, section, "dtb");
    if ( name.s )
    {
        truncate_string(name.s);
        read_file(dir_handle, s2w(&name), &dtb, max_addr);
        PrintStr(L"Using FDT from file ");
        PrintStr(name.w);
        PrintStr(L"\r\n");
        efi_bs->FreePool(name.w);
    }
    else
    {
        /* Get DTB from configuration table. */
        dtb.ptr = lookup_fdt_config_table(SystemTable);
        if ( dtb.ptr )
        {
            PrintStr(L"Using FDT from EFI configuration table\r\n");
            /* Set dtb.size to zero so config table memory is not freed. */
            dtb.size = 0;
        }
    }

    /*
     * Allocate space for new FDT, making sure we have enough space
     * for the fields we are adding, so we don't have to deal
     * with increasing the size again later, which complicates
     * things.  Use the size of the configuration file as an uppper
     * bound on how much size can be added based on configuration
     * file contents.
     */
    return fdt_increase_size(&dtb, cfg.size + EFI_PAGE_SIZE);
}


#define COMPAT_BUF_SIZE 500 /* FDT string buffer size. */
unsigned long efi_entry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_GUID loaded_image_guid = LOADED_IMAGE_PROTOCOL;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_FILE_HANDLE dir_handle;
    EFI_STATUS status;
    union string section = { NULL }, cmdline = { NULL }, name = { NULL };
    CHAR16 * file_name,*cfg_file_name = NULL,*image_name = NULL;
    bool_t base_video = 0;
    int node;
    int chosen;
    int addr_len, size_len;
    char *options;
    char compat_buf[COMPAT_BUF_SIZE];
    int compat_len = 0;
    unsigned long desc_size;
    UINT32 desc_ver = 0;
    unsigned long map_key = 0;

    efi_ih = ImageHandle;
    efi_bs = SystemTable->BootServices;
    StdOut = SystemTable->ConOut;

    /* Check if we were booted by the EFI firmware */
    if ( SystemTable->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE )
        goto fail;

    /* Get loaded image protocol */
    status = efi_bs->HandleProtocol(ImageHandle, &loaded_image_guid,
                                    (void **)&loaded_image);
    if ( status != EFI_SUCCESS )
        blexit(L"ERROR - no loaded image protocol\r\n");

    PrintStr(L"Xen " __stringify(XEN_VERSION)"." __stringify(XEN_SUBVERSION)
             XEN_EXTRAVERSION " (c/s " XEN_CHANGESET ") EFI loader\r\n");

    if ( (unsigned long)loaded_image->ImageBase & ((1 << 20) - 1) )
        blexit(L"Xen must be loaded at a 2MByte boundary.");

    /* Get the file system interface. */
    dir_handle = get_parent_handle(loaded_image, &file_name);

    handle_cmdline(loaded_image, &cfg_file_name, &base_video, &image_name,
                   &section.w, &cmdline.w);

    if ( cmdline.w )
        w2s(&cmdline);

    /* Open and read config file */
    read_config_file(&dir_handle, &cfg, cfg_file_name,
                     &section, file_name);

    new_fdt = create_new_fdt(SystemTable, dir_handle, &cfg, section.s);
    if ( !new_fdt )
        blexit(L"Unable to create new FDT\r\n");

    chosen = setup_chosen_node(new_fdt, &addr_len, &size_len);
    if ( chosen < 0 )
        blexit(L"Unable to setup chosen node\r\n");


    name.s = get_value(&cfg, section.s, "kernel");
    if ( !name.s )
        blexit(L"No Dom0 kernel image specified.");
    options = truncate_string(name.s);
    if ( options )
        fdt_setprop_string(new_fdt, chosen, "xen,dom0-bootargs", options);
    s2w(&name);
    read_file(dir_handle, name.w, &kernel, max_addr);

    node = fdt_add_subnode(new_fdt, chosen, "kernel");
    if ( node < 0 )
        blexit(L"Error adding dom0 FDT node.");

    compat_len = 0;
    compat_len += snprintf(compat_buf + compat_len,
                           COMPAT_BUF_SIZE - compat_len,
                           "multiboot,kernel") + 1;
    if ( compat_len > COMPAT_BUF_SIZE )
        blexit(L"FDT string overflow");
    compat_len += snprintf(compat_buf + compat_len,
                           COMPAT_BUF_SIZE - compat_len,
                           "multiboot,module") + 1;
    if ( compat_len > COMPAT_BUF_SIZE )
        blexit(L"FDT string overflow");
    if ( fdt_setprop(new_fdt, node, "compatible", compat_buf, compat_len) < 0 )
        blexit(L"unable to set compatible property.");
    fdt_set_reg(new_fdt, node, addr_len, size_len, kernel.addr, kernel.size);
    efi_bs->FreePool(name.w);


    name.s = get_value(&cfg, section.s, "ramdisk");
    if ( name.s )
    {
        truncate_string(name.s);
        read_file(dir_handle, s2w(&name), &ramdisk, max_addr);

        node = fdt_add_subnode(new_fdt, chosen, "ramdisk");
        if ( node < 0 )
            blexit(L"Error adding ramdisk FDT node.");

        compat_len = 0;
        compat_len += snprintf(compat_buf + compat_len,
                               COMPAT_BUF_SIZE - compat_len,
                               "multiboot,ramdisk") + 1;
        if ( compat_len > COMPAT_BUF_SIZE )
            blexit(L"FDT string overflow");
        compat_len += snprintf(compat_buf + compat_len,
                               COMPAT_BUF_SIZE - compat_len,
                               "multiboot,module") + 1;
        if ( compat_len > COMPAT_BUF_SIZE )
            blexit(L"FDT string overflow");
        if ( fdt_setprop(new_fdt, node, "compatible", compat_buf, compat_len) < 0 )
            blexit(L"unable to set compatible property.");
        fdt_set_reg(new_fdt, node, addr_len, size_len, ramdisk.addr,
                    ramdisk.size);
        efi_bs->FreePool(name.w);
    }


    /*
     * cmdline has remaining options from EFI command line.  Prepend these
     * to the options from the configuration file.  Put the image name at
     * the beginning of the bootargs.
     *
     */
    if ( image_name )
    {
        name.w = image_name;
        w2s(&name);
    }
    else
        name.s = "xen";

    compat_len = 0;
    compat_len += snprintf(compat_buf + compat_len,
                           COMPAT_BUF_SIZE - compat_len, "%s", name.s);
    if ( compat_len >= COMPAT_BUF_SIZE )
        blexit(L"FDT string overflow");
    if ( cmdline.s )
    {
        compat_len += snprintf(compat_buf + compat_len,
                               COMPAT_BUF_SIZE - compat_len, " %s", cmdline.s);
        if ( compat_len >= COMPAT_BUF_SIZE )
            blexit(L"FDT string overflow");
    }
    name.s = get_value(&cfg, section.s, "options");
    if ( name.s )
    {
        compat_len += snprintf(compat_buf + compat_len,
                               COMPAT_BUF_SIZE - compat_len, " %s", name.s);
        if ( compat_len >= COMPAT_BUF_SIZE )
            blexit(L"FDT string overflow");
    }


    /* Free config file buffer */
    efi_bs->FreePages(cfg.addr, PFN_UP(cfg.size));
    cfg.addr = 0;

    if ( fdt_setprop_string(new_fdt, chosen, "xen,xen-bootargs", compat_buf) < 0 )
        blexit(L"unable to set xen,xen-bootargs property.");

    status = efi_get_memory_map(SystemTable, &mmap_ptr, &mmap_size,
                                &desc_size, &desc_ver, &map_key);
    if ( status != EFI_SUCCESS )
        blexit(L"unable to get EFI memory map");


    status = fdt_add_uefi_nodes(SystemTable, new_fdt, mmap_ptr,
                                mmap_size, desc_size, desc_ver);
    if ( status != EFI_SUCCESS )
    {
        if ( status == EFI_BUFFER_TOO_SMALL )
            PrintStr(L"ERROR: FDT buffer too small\r\n");
        blexit(L"Unable to create new FDT with UEFI nodes");
    }

    status = efi_bs->ExitBootServices(ImageHandle, map_key);
    if ( status != EFI_SUCCESS )
        blexit(L"Unable to exit boot services.");

    /*
     *  Put available EFI memory into bootinfo memory map.
     */
    efi_process_memory_map_bootinfo(mmap_ptr, mmap_size, desc_size);

    return((unsigned long)new_fdt);


fail:
    blexit(L"ERROR: Unable to start XEN\r\n");
}


void __init noreturn blexit(const CHAR16 *str)
{
    if ( str )
        PrintStr((CHAR16 *)str);
    PrintStr(newline);

    if ( cfg.addr )
        efi_bs->FreePages(cfg.addr, PFN_UP(cfg.size));
    if ( kernel.addr )
        efi_bs->FreePages(kernel.addr, PFN_UP(kernel.size));
    if ( ramdisk.addr )
        efi_bs->FreePages(ramdisk.addr, PFN_UP(ramdisk.size));
    if ( dtb.addr && dtb.size )
        efi_bs->FreePages(dtb.addr, PFN_UP(dtb.size));
    if ( mmap_ptr )
        efi_bs->FreePool(mmap_ptr);

    efi_bs->Exit(efi_ih, EFI_SUCCESS, 0, NULL);
    unreachable(); /* not reached */
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
