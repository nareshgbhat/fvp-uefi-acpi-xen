#ifndef __EFI_SHARED_H__
#define __EFI_SHARED_H__

#include <efi/efidef.h>
#include <xen/init.h>


union string {
    CHAR16 *w;
    char *s;
    const char *cs;
};

struct file {
    UINTN size;
    union {
        EFI_PHYSICAL_ADDRESS addr;
        void *ptr;
    };
};


#define PrintStr(s) StdOut->OutputString(StdOut, s)
#define PrintErr(s) StdErr->OutputString(StdErr, s)



CHAR16 * FormatDec(UINT64 Val, CHAR16 *Buffer);
CHAR16 * FormatHex(UINT64 Val, UINTN Width, CHAR16 *Buffer);

void __init DisplayUint(UINT64 Val, INTN Width);
CHAR16 *__init wstrcpy(CHAR16 *d, const CHAR16 *s);
int __init wstrcmp(const CHAR16 *s1, const CHAR16 *s2);
int __init wstrncmp(const CHAR16 *s1, const CHAR16 *s2, UINTN n);
CHAR16 *__init s2w(union string *str);
char *__init w2s(const union string *str);
bool_t __init match_guid(const EFI_GUID *guid1, const EFI_GUID *guid2);

void __init PrintErrMesg(const CHAR16 *mesg, EFI_STATUS ErrCode);
EFI_FILE_HANDLE __init get_parent_handle(EFI_LOADED_IMAGE *loaded_image,
                                         CHAR16 **leaf);
CHAR16 *__init point_tail(CHAR16 *fn);
bool_t __init read_file(EFI_FILE_HANDLE dir_handle, CHAR16 *name,
                               struct file *file, EFI_PHYSICAL_ADDRESS max_addr);
void __init pre_parse(const struct file *cfg);
char *__init get_value(const struct file *cfg, const char *section,
                       const char *item);

char * __init truncate_string(char *s);

bool_t __init read_config_file(EFI_FILE_HANDLE *cfg_dir_handle,
                             struct file *cfg, CHAR16 *cfg_file_name,
                             union string *section,
                             CHAR16 *xen_file_name);
unsigned int __init get_argv(unsigned int argc, CHAR16 **argv, CHAR16 *cmdline,
                             UINTN cmdsize, CHAR16 **cmdline_remain);
bool_t __init handle_cmdline(EFI_LOADED_IMAGE *loaded_image,
                           CHAR16 **cfg_file_name, bool_t *base_video,
                           CHAR16 **image_name, CHAR16 **section_name,
                           CHAR16 **cmdline_remain);
#endif


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
