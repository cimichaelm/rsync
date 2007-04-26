/* 
   Unix SMB/Netbios implementation.
   Version 2.2.x
   Portable SMB ACL interface
   Copyright (C) Jeremy Allison 2000
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifdef SUPPORT_ACLS

#ifdef HAVE_SYS_ACL_H
#include <sys/acl.h>
#endif
#ifdef HAVE_ACL_LIBACL_H
#include <acl/libacl.h>
#endif

#define SMB_MALLOC(cnt) new_array(char, cnt)
#define SMB_MALLOC_P(obj) new_array(obj, 1)
#define SMB_MALLOC_ARRAY(obj, cnt) new_array(obj, cnt)
#define SMB_REALLOC(mem, cnt) realloc_array(mem, char, cnt)
#define slprintf snprintf

#if defined HAVE_POSIX_ACLS

/* This is an identity mapping (just remove the SMB_). */

#define SMB_ACL_TAG_T		acl_tag_t
#define SMB_ACL_TYPE_T		acl_type_t
#define SMB_ACL_PERMSET_T	acl_permset_t
#define SMB_ACL_PERM_T		acl_perm_t
#define SMB_ACL_READ		ACL_READ
#define SMB_ACL_WRITE		ACL_WRITE
#define SMB_ACL_EXECUTE		ACL_EXECUTE

/* Types of ACLs. */
#define SMB_ACL_USER		ACL_USER
#define SMB_ACL_USER_OBJ	ACL_USER_OBJ
#define SMB_ACL_GROUP		ACL_GROUP
#define SMB_ACL_GROUP_OBJ	ACL_GROUP_OBJ
#define SMB_ACL_OTHER		ACL_OTHER
#define SMB_ACL_MASK		ACL_MASK

#define SMB_ACL_T		acl_t

#define SMB_ACL_ENTRY_T		acl_entry_t

#define SMB_ACL_FIRST_ENTRY	ACL_FIRST_ENTRY
#define SMB_ACL_NEXT_ENTRY	ACL_NEXT_ENTRY

#define SMB_ACL_TYPE_ACCESS	ACL_TYPE_ACCESS
#define SMB_ACL_TYPE_DEFAULT	ACL_TYPE_DEFAULT

#elif defined HAVE_TRU64_ACLS

/* This is for DEC/Compaq Tru64 UNIX */

#define SMB_ACL_TAG_T		acl_tag_t
#define SMB_ACL_TYPE_T		acl_type_t
#define SMB_ACL_PERMSET_T	acl_permset_t
#define SMB_ACL_PERM_T		acl_perm_t
#define SMB_ACL_READ		ACL_READ
#define SMB_ACL_WRITE		ACL_WRITE
#define SMB_ACL_EXECUTE		ACL_EXECUTE

/* Types of ACLs. */
#define SMB_ACL_USER		ACL_USER
#define SMB_ACL_USER_OBJ	ACL_USER_OBJ
#define SMB_ACL_GROUP		ACL_GROUP
#define SMB_ACL_GROUP_OBJ	ACL_GROUP_OBJ
#define SMB_ACL_OTHER		ACL_OTHER
#define SMB_ACL_MASK		ACL_MASK

#define SMB_ACL_T		acl_t

#define SMB_ACL_ENTRY_T		acl_entry_t

#define SMB_ACL_FIRST_ENTRY	0
#define SMB_ACL_NEXT_ENTRY	1

#define SMB_ACL_TYPE_ACCESS	ACL_TYPE_ACCESS
#define SMB_ACL_TYPE_DEFAULT	ACL_TYPE_DEFAULT

#elif defined HAVE_UNIXWARE_ACLS || defined HAVE_SOLARIS_ACLS
/*
 * Donated by Michael Davidson <md@sco.COM> for UnixWare / OpenUNIX.
 * Modified by Toomas Soome <tsoome@ut.ee> for Solaris.
 */

/* SVR4.2 ES/MP ACLs */
typedef int SMB_ACL_TAG_T;
typedef int SMB_ACL_TYPE_T;
typedef ushort *SMB_ACL_PERMSET_T;
typedef ushort SMB_ACL_PERM_T;
#define SMB_ACL_READ		4
#define SMB_ACL_WRITE		2
#define SMB_ACL_EXECUTE		1

/* Types of ACLs. */
#define SMB_ACL_USER		USER
#define SMB_ACL_USER_OBJ	USER_OBJ
#define SMB_ACL_GROUP		GROUP
#define SMB_ACL_GROUP_OBJ	GROUP_OBJ
#define SMB_ACL_OTHER		OTHER_OBJ
#define SMB_ACL_MASK		CLASS_OBJ

typedef struct SMB_ACL_T {
	int size;
	int count;
	int next;
	struct acl acl[1];
} *SMB_ACL_T;

typedef struct acl *SMB_ACL_ENTRY_T;

#define SMB_ACL_FIRST_ENTRY	0
#define SMB_ACL_NEXT_ENTRY	1

#define SMB_ACL_TYPE_ACCESS	0
#define SMB_ACL_TYPE_DEFAULT	1

#ifdef __CYGWIN__
#define SMB_ACL_LOSES_SPECIAL_MODE_BITS
#endif

#elif defined HAVE_HPUX_ACLS

/*
 * Based on the Solaris & UnixWare code.
 */

#undef GROUP
#include <sys/aclv.h>

/* SVR4.2 ES/MP ACLs */
typedef int SMB_ACL_TAG_T;
typedef int SMB_ACL_TYPE_T;
typedef ushort *SMB_ACL_PERMSET_T;
typedef ushort SMB_ACL_PERM_T;
#define SMB_ACL_READ		4
#define SMB_ACL_WRITE		2
#define SMB_ACL_EXECUTE		1

/* Types of ACLs. */
#define SMB_ACL_USER		USER
#define SMB_ACL_USER_OBJ	USER_OBJ
#define SMB_ACL_GROUP		GROUP
#define SMB_ACL_GROUP_OBJ	GROUP_OBJ
#define SMB_ACL_OTHER		OTHER_OBJ
#define SMB_ACL_MASK		CLASS_OBJ

typedef struct SMB_ACL_T {
	int size;
	int count;
	int next;
	struct acl acl[1];
} *SMB_ACL_T;

typedef struct acl *SMB_ACL_ENTRY_T;

#define SMB_ACL_FIRST_ENTRY	0
#define SMB_ACL_NEXT_ENTRY	1

#define SMB_ACL_TYPE_ACCESS	0
#define SMB_ACL_TYPE_DEFAULT	1

#elif defined HAVE_IRIX_ACLS

#define SMB_ACL_TAG_T		acl_tag_t
#define SMB_ACL_TYPE_T		acl_type_t
#define SMB_ACL_PERMSET_T	acl_permset_t
#define SMB_ACL_PERM_T		acl_perm_t
#define SMB_ACL_READ		ACL_READ
#define SMB_ACL_WRITE		ACL_WRITE
#define SMB_ACL_EXECUTE		ACL_EXECUTE

/* Types of ACLs. */
#define SMB_ACL_USER		ACL_USER
#define SMB_ACL_USER_OBJ	ACL_USER_OBJ
#define SMB_ACL_GROUP		ACL_GROUP
#define SMB_ACL_GROUP_OBJ	ACL_GROUP_OBJ
#define SMB_ACL_OTHER		ACL_OTHER_OBJ
#define SMB_ACL_MASK		ACL_MASK

typedef struct SMB_ACL_T {
	int next;
	BOOL freeaclp;
	struct acl *aclp;
} *SMB_ACL_T;

#define SMB_ACL_ENTRY_T		acl_entry_t

#define SMB_ACL_FIRST_ENTRY	0
#define SMB_ACL_NEXT_ENTRY	1

#define SMB_ACL_TYPE_ACCESS	ACL_TYPE_ACCESS
#define SMB_ACL_TYPE_DEFAULT	ACL_TYPE_DEFAULT

#elif defined HAVE_AIX_ACLS

/* Donated by Medha Date, mdate@austin.ibm.com, for IBM */

#include "/usr/include/acl.h"

typedef uint *SMB_ACL_PERMSET_T;
 
struct acl_entry_link{
	struct acl_entry_link *prevp;
	struct new_acl_entry *entryp;
	struct acl_entry_link *nextp;
	int count;
};

struct new_acl_entry{
	unsigned short ace_len;
	unsigned short ace_type;
	unsigned int ace_access;
	struct ace_id ace_id[1];
};

#define SMB_ACL_ENTRY_T		struct new_acl_entry*
#define SMB_ACL_T		struct acl_entry_link*
 
#define SMB_ACL_TAG_T		unsigned short
#define SMB_ACL_TYPE_T		int
#define SMB_ACL_PERM_T		uint
#define SMB_ACL_READ		S_IRUSR
#define SMB_ACL_WRITE		S_IWUSR
#define SMB_ACL_EXECUTE		S_IXUSR

/* Types of ACLs. */
#define SMB_ACL_USER		ACEID_USER
#define SMB_ACL_USER_OBJ	3
#define SMB_ACL_GROUP		ACEID_GROUP
#define SMB_ACL_GROUP_OBJ	4
#define SMB_ACL_OTHER		5
#define SMB_ACL_MASK		6


#define SMB_ACL_FIRST_ENTRY	1
#define SMB_ACL_NEXT_ENTRY	2

#define SMB_ACL_TYPE_ACCESS	0
#define SMB_ACL_TYPE_DEFAULT	1

#else /* No ACLs. */

/* No ACLS - fake it. */
#define SMB_ACL_TAG_T		int
#define SMB_ACL_TYPE_T		int
#define SMB_ACL_PERMSET_T	mode_t
#define SMB_ACL_PERM_T		mode_t
#define SMB_ACL_READ		S_IRUSR
#define SMB_ACL_WRITE		S_IWUSR
#define SMB_ACL_EXECUTE		S_IXUSR

/* Types of ACLs. */
#define SMB_ACL_USER		0
#define SMB_ACL_USER_OBJ	1
#define SMB_ACL_GROUP		2
#define SMB_ACL_GROUP_OBJ	3
#define SMB_ACL_OTHER		4
#define SMB_ACL_MASK		5

typedef struct SMB_ACL_T {
	int dummy;
} *SMB_ACL_T;

typedef struct SMB_ACL_ENTRY_T {
	int dummy;
} *SMB_ACL_ENTRY_T;

#define SMB_ACL_FIRST_ENTRY	0
#define SMB_ACL_NEXT_ENTRY	1

#define SMB_ACL_TYPE_ACCESS	0
#define SMB_ACL_TYPE_DEFAULT	1

#endif /* No ACLs. */

int sys_acl_get_entry(SMB_ACL_T the_acl, int entry_id, SMB_ACL_ENTRY_T *entry_p);
int sys_acl_get_tag_type(SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p);
int sys_acl_get_permset(SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p);
void *sys_acl_get_qualifier(SMB_ACL_ENTRY_T entry_d);
SMB_ACL_T sys_acl_get_file(const char *path_p, SMB_ACL_TYPE_T type);
SMB_ACL_T sys_acl_get_fd(int fd);
int sys_acl_clear_perms(SMB_ACL_PERMSET_T permset);
int sys_acl_add_perm(SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm);
int sys_acl_get_perm(SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm);
char *sys_acl_to_text(SMB_ACL_T the_acl, ssize_t *plen);
SMB_ACL_T sys_acl_init(int count);
int sys_acl_create_entry(SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry);
int sys_acl_set_tag_type(SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype);
int sys_acl_set_qualifier(SMB_ACL_ENTRY_T entry, void *qual);
int sys_acl_set_permset(SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset);
int sys_acl_valid(SMB_ACL_T theacl);
int sys_acl_set_file(const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl);
int sys_acl_set_fd(int fd, SMB_ACL_T theacl);
int sys_acl_delete_def_file(const char *name);
int sys_acl_free_text(char *text);
int sys_acl_free_acl(SMB_ACL_T the_acl);
int sys_acl_free_qualifier(void *qual, SMB_ACL_TAG_T tagtype);
int no_acl_syscall_error(int err);

#endif /* SUPPORT_ACLS */