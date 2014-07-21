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
