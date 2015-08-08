/*
 * Syscall wrappers to ensure that nothing gets done in dry_run mode
 * and to handle system peculiarities.
 *
 * Copyright (C) 1998 Andrew Tridgell
 * Copyright (C) 2002 Martin Pool
 * Copyright (C) 2003-2014 Wayne Davison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, visit the http://fsf.org website.
 */

#include "rsync.h"

#if !defined MKNOD_CREATES_SOCKETS && defined HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_SYS_ATTR_H
#include <sys/attr.h>
#endif

#if defined HAVE_SYS_FALLOCATE && !defined HAVE_FALLOCATE
#include <sys/syscall.h>
#endif
#ifdef ENABLE_LOCKING
#include <unistd.h>
#include <fcntl.h>
#endif

extern int dry_run;
extern int am_root;
extern int am_sender;
extern int read_only;
extern int list_only;
extern int preserve_perms;
extern int preserve_executability;
extern int skipreadlock;
extern int waitreadlock;

#define RETURN_ERROR_IF(x,e) \
	do { \
		if (x) { \
			errno = (e); \
			return -1; \
		} \
	} while (0)

#define RETURN_ERROR_IF_RO_OR_LO RETURN_ERROR_IF(read_only || list_only, EROFS)

int do_unlink(const char *fname)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return unlink(fname);
}

#ifdef SUPPORT_LINKS
int do_symlink(const char *lnk, const char *fname)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

#if defined NO_SYMLINK_XATTRS || defined NO_SYMLINK_USER_XATTRS
	/* For --fake-super, we create a normal file with mode 0600
	 * and write the lnk into it. */
	if (am_root < 0) {
		int ok, len = strlen(lnk);
		int fd = open(fname, O_WRONLY|O_CREAT|O_TRUNC, S_IWUSR|S_IRUSR);
		if (fd < 0)
			return -1;
		ok = write(fd, lnk, len) == len;
		if (close(fd) < 0)
			ok = 0;
		return ok ? 0 : -1;
	}
#endif

	return symlink(lnk, fname);
}

#if defined NO_SYMLINK_XATTRS || defined NO_SYMLINK_USER_XATTRS
ssize_t do_readlink(const char *path, char *buf, size_t bufsiz)
{
	/* For --fake-super, we read the link from the file. */
	if (am_root < 0) {
		int fd = do_open_nofollow(path, O_RDONLY);
		if (fd >= 0) {
			int len = read(fd, buf, bufsiz);
			close(fd);
			return len;
		}
		if (errno != ELOOP)
			return -1;
		/* A real symlink needs to be turned into a fake one on the receiving
		 * side, so tell the generator that the link has no length. */
		if (!am_sender)
			return 0;
		/* Otherwise fall through and let the sender report the real length. */
	}

	return readlink(path, buf, bufsiz);
}
#endif
#endif

#ifdef HAVE_LINK
int do_link(const char *fname1, const char *fname2)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return link(fname1, fname2);
}
#endif

int do_lchown(const char *path, uid_t owner, gid_t group)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
#ifndef HAVE_LCHOWN
#define lchown chown
#endif
	return lchown(path, owner, group);
}

int do_mknod(const char *pathname, mode_t mode, dev_t dev)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

	/* For --fake-super, we create a normal file with mode 0600. */
	if (am_root < 0) {
		int fd = open(pathname, O_WRONLY|O_CREAT|O_TRUNC, S_IWUSR|S_IRUSR);
		if (fd < 0 || close(fd) < 0)
			return -1;
		return 0;
	}

#if !defined MKNOD_CREATES_FIFOS && defined HAVE_MKFIFO
	if (S_ISFIFO(mode))
		return mkfifo(pathname, mode);
#endif
#if !defined MKNOD_CREATES_SOCKETS && defined HAVE_SYS_UN_H
	if (S_ISSOCK(mode)) {
		int sock;
		struct sockaddr_un saddr;
		unsigned int len = strlcpy(saddr.sun_path, pathname, sizeof saddr.sun_path);
		if (len >= sizeof saddr.sun_path) {
			errno = ENAMETOOLONG;
			return -1;
		}
#ifdef HAVE_SOCKADDR_UN_LEN
		saddr.sun_len = len + 1;
#endif
		saddr.sun_family = AF_UNIX;

		if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0
		    || (unlink(pathname) < 0 && errno != ENOENT)
		    || (bind(sock, (struct sockaddr*)&saddr, sizeof saddr)) < 0)
			return -1;
		close(sock);
#ifdef HAVE_CHMOD
		return do_chmod(pathname, mode);
#else
		return 0;
#endif
	}
#endif
#ifdef HAVE_MKNOD
	return mknod(pathname, mode, dev);
#else
	return -1;
#endif
}

int do_rmdir(const char *pathname)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return rmdir(pathname);
}

#ifdef ENABLE_LOCKING
#pragma message "file locking enabled."
#define LOCK_FCNTL 1
#ifdef LOCK_FCNTL
#define LOCK_SHARED F_RDLCK
#define LOCK_EXCLUSIVE F_WRLCK
#endif
#ifdef LOCK_FLOCK
#define LOCK_SHARED LOCK_SH
#define LOCK_EXCLUSIVE LOCK_EX
#endif
#endif

#ifdef LOCK_FCNTL
int do_open_lock(const char *pathname, int flags, mode_t mode)
{
        int fd, lock_type;
	int flg_checklock, flg_setlock;
	int rcode; /* return code */
	int tries; /* retry counter */
	int more; /* loop controller */
	int lock_delay; /* delay to wait for locking */
	int lock_tries; /* number of times to retry */
	int errcode; /* store errno */
	struct flock lock; /* lock structure */

	lock_delay = 5000;
	lock_tries = 10;
	flg_checklock = 0;
	flg_setlock = 0;

	if (skipreadlock || waitreadlock) {
	  flg_checklock=1;
	  flg_setlock=1;
	}
	
	if (DEBUG_GTE(SEND, 1)) {
	  if (flg_checklock)
	    rprintf(FINFO, "INFO: checklock is enabled\n");
	  if (flg_setlock)
	    rprintf(FINFO, "INFO: setlock is enabled\n");
	  if (skipreadlock)
	    rprintf(FINFO, "INFO: skipreadlock is enabled\n");
	  if (waitreadlock)
	    rprintf(FINFO, "INFO: waitreadlock is enabled\n");
	}

	if (flags != O_RDONLY) {
		RETURN_ERROR_IF(dry_run, 0);
		RETURN_ERROR_IF_RO_OR_LO;
	}

	/* open file */
	fd = open(pathname, flags | O_BINARY, mode);
	if (! flg_checklock) return fd;

	if (fd >= 0) {
	  if (flags & O_WRONLY || flags & O_RDWR) {
	    lock_type = LOCK_EXCLUSIVE;
	  } else {
	    lock_type = LOCK_SHARED;
	  }

	  /* obtain a lock on the file */

	  lock.l_type = lock_type;
	  lock.l_start = 0;
	  lock.l_whence = SEEK_SET;
	  lock.l_len = 0;
	  tries=0;
	  more = 1;
	  while (more) {
	    if ((rcode=fcntl(fd,F_GETLK,&lock)) < 0) {
	      /* check errno */
	      errcode = errno;
	      if (DEBUG_GTE(SEND, 1)) {
		rprintf(FINFO, "ERROR: fcntl GETLK. wait and try again.\n");
		rsyserr(FINFO, errcode, "ERROR: fcntl SETLK. fd=%d", fd);
	      }
	      usleep(lock_delay);
	      tries++;
	      if (tries >= lock_tries) {
		return fd;
	      } else continue;
	    }
	    if (lock.l_type == F_UNLCK) {
	      //file is unlocked
	      if (flg_setlock) {
		lock.l_type = lock_type;
		lock.l_start = 0;
		lock.l_whence = SEEK_SET;
		lock.l_len = 0;
		//set the lock
		if ((rcode=fcntl(fd,F_SETLK,&lock))<0) {
		  /* check errno */
		  errcode = errno;
		  if (DEBUG_GTE(SEND, 1)) {
		    rprintf(FINFO, "ERROR: fcntl SETLK. errno=%d, wait and try agian.\n",errcode);
		    rsyserr(FINFO, errcode,"ERROR: fcntl SETLK. fd=%d",fd);
		  }
		  tries++;
		  usleep(tries * lock_delay);
		  if (tries == lock_tries) return fd;
		  else continue;
		} else {
		  if (DEBUG_GTE(SEND, 1))
		    rprintf(FINFO, "read file lock granted.\n");
		  /* lock successful */
		  more = 0;
		  break;
		}
	      } else {
		  more = 0;
	      }
	    } else {
	      /* file is locked */
	      if (skipreadlock) {
		if (DEBUG_GTE(SEND, 1))
		  rprintf(FINFO, "skipping locked file.\n");
		close(fd);
		return -1;
	      } else {
		if (DEBUG_GTE(SEND, 1))
		  rprintf(FINFO, "wating on file lock.\n");
		usleep(lock_delay);
		tries++;
		if (tries >= lock_tries) {
		  return fd;
		} else continue;
	      }
	    }
	  }
	}

	return fd;
}
#else
#ifdef LOCK_FLOCK
int do_open_lock(const char *pathname, int flags, mode_t mode)
{
        int fd, lock_type;

	if (flags != O_RDONLY) {
		RETURN_ERROR_IF(dry_run, 0);
		RETURN_ERROR_IF_RO_OR_LO;
	}

	if (flags & O_WRONLY || flags & O_RDWR) {
	  lock_type = LOCK_EXCLUSIVE;
	} else {
	  lock_type = LOCK_SHARED:
	}


	/* open file */
	fd = open(pathname, flags | O_BINARY, mode);

	if (fd >= 0) {
	  /* obtain a lock on the file */
	  flock(fd, lock_type);
	}

	return fd
}
#else
int do_open_lock(const char *pathname, int flags, mode_t mode)
{
  return do_open(pathname, flags, mode);
}
#endif
#endif


int do_open(const char *pathname, int flags, mode_t mode)
{
	if (flags != O_RDONLY) {
		RETURN_ERROR_IF(dry_run, 0);
		RETURN_ERROR_IF_RO_OR_LO;
	}

	return open(pathname, flags | O_BINARY, mode);
}

#ifdef HAVE_CHMOD
int do_chmod(const char *path, mode_t mode)
{
	int code;
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
#ifdef HAVE_LCHMOD
	code = lchmod(path, mode & CHMOD_BITS);
#else
	if (S_ISLNK(mode)) {
# if defined HAVE_SETATTRLIST
		struct attrlist attrList;
		uint32_t m = mode & CHMOD_BITS; /* manpage is wrong: not mode_t! */

		memset(&attrList, 0, sizeof attrList);
		attrList.bitmapcount = ATTR_BIT_MAP_COUNT;
		attrList.commonattr = ATTR_CMN_ACCESSMASK;
		code = setattrlist(path, &attrList, &m, sizeof m, FSOPT_NOFOLLOW);
# else
		code = 1;
# endif
	} else
		code = chmod(path, mode & CHMOD_BITS); /* DISCOURAGED FUNCTION */
#endif /* !HAVE_LCHMOD */
	if (code != 0 && (preserve_perms || preserve_executability))
		return code;
	return 0;
}
#endif

int do_rename(const char *fname1, const char *fname2)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return rename(fname1, fname2);
}

#ifdef HAVE_FTRUNCATE
int do_ftruncate(int fd, OFF_T size)
{
	int ret;

	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

	do {
		ret = ftruncate(fd, size);
	} while (ret < 0 && errno == EINTR);

	return ret;
}
#endif

void trim_trailing_slashes(char *name)
{
	int l;
	/* Some BSD systems cannot make a directory if the name
	 * contains a trailing slash.
	 * <http://www.opensource.apple.com/bugs/X/BSD%20Kernel/2734739.html> */

	/* Don't change empty string; and also we can't improve on
	 * "/" */

	l = strlen(name);
	while (l > 1) {
		if (name[--l] != '/')
			break;
		name[l] = '\0';
	}
}

int do_mkdir(char *fname, mode_t mode)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	trim_trailing_slashes(fname);
	return mkdir(fname, mode);
}

/* like mkstemp but forces permissions */
int do_mkstemp(char *template, mode_t perms)
{
	RETURN_ERROR_IF(dry_run, 0);
	RETURN_ERROR_IF(read_only, EROFS);
	perms |= S_IWUSR;

#if defined HAVE_SECURE_MKSTEMP && defined HAVE_FCHMOD && (!defined HAVE_OPEN64 || defined HAVE_MKSTEMP64)
	{
		int fd = mkstemp(template);
		if (fd == -1)
			return -1;
		if (fchmod(fd, perms) != 0 && preserve_perms) {
			int errno_save = errno;
			close(fd);
			unlink(template);
			errno = errno_save;
			return -1;
		}
#if defined HAVE_SETMODE && O_BINARY
		setmode(fd, O_BINARY);
#endif
		return fd;
	}
#else
	if (!mktemp(template))
		return -1;
	return do_open(template, O_RDWR|O_EXCL|O_CREAT, perms);
#endif
}

int do_stat(const char *fname, STRUCT_STAT *st)
{
#ifdef USE_STAT64_FUNCS
	return stat64(fname, st);
#else
	return stat(fname, st);
#endif
}

int do_lstat(const char *fname, STRUCT_STAT *st)
{
#ifdef SUPPORT_LINKS
# ifdef USE_STAT64_FUNCS
	return lstat64(fname, st);
# else
	return lstat(fname, st);
# endif
#else
	return do_stat(fname, st);
#endif
}

int do_fstat(int fd, STRUCT_STAT *st)
{
#ifdef USE_STAT64_FUNCS
	return fstat64(fd, st);
#else
	return fstat(fd, st);
#endif
}

OFF_T do_lseek(int fd, OFF_T offset, int whence)
{
#ifdef HAVE_LSEEK64
#if !SIZEOF_OFF64_T
	OFF_T lseek64();
#else
	off64_t lseek64();
#endif
	return lseek64(fd, offset, whence);
#else
	return lseek(fd, offset, whence);
#endif
}

#ifdef HAVE_UTIMENSAT
int do_utimensat(const char *fname, time_t modtime, uint32 mod_nsec)
{
	struct timespec t[2];

	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

	t[0].tv_sec = 0;
	t[0].tv_nsec = UTIME_NOW;
	t[1].tv_sec = modtime;
	t[1].tv_nsec = mod_nsec;
	return utimensat(AT_FDCWD, fname, t, AT_SYMLINK_NOFOLLOW);
}
#endif

#ifdef HAVE_LUTIMES
int do_lutimes(const char *fname, time_t modtime, uint32 mod_nsec)
{
	struct timeval t[2];

	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

	t[0].tv_sec = time(NULL);
	t[0].tv_usec = 0;
	t[1].tv_sec = modtime;
	t[1].tv_usec = mod_nsec / 1000;
	return lutimes(fname, t);
}
#endif

#ifdef HAVE_UTIMES
int do_utimes(const char *fname, time_t modtime, uint32 mod_nsec)
{
	struct timeval t[2];

	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

	t[0].tv_sec = time(NULL);
	t[0].tv_usec = 0;
	t[1].tv_sec = modtime;
	t[1].tv_usec = mod_nsec / 1000;
	return utimes(fname, t);
}

#elif defined HAVE_UTIME
int do_utime(const char *fname, time_t modtime, UNUSED(uint32 mod_nsec))
{
#ifdef HAVE_STRUCT_UTIMBUF
	struct utimbuf tbuf;
#else
	time_t t[2];
#endif

	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

# ifdef HAVE_STRUCT_UTIMBUF
	tbuf.actime = time(NULL);
	tbuf.modtime = modtime;
	return utime(fname, &tbuf);
# else
	t[0] = time(NULL);
	t[1] = modtime;
	return utime(fname, t);
# endif
}

#else
#error Need utimes or utime function.
#endif

#ifdef SUPPORT_PREALLOCATION
int do_fallocate(int fd, OFF_T offset, OFF_T length)
{
#ifdef FALLOC_FL_KEEP_SIZE
#define DO_FALLOC_OPTIONS FALLOC_FL_KEEP_SIZE
#else
#define DO_FALLOC_OPTIONS 0
#endif
	RETURN_ERROR_IF(dry_run, 0);
	RETURN_ERROR_IF_RO_OR_LO;
#if defined HAVE_FALLOCATE
	return fallocate(fd, DO_FALLOC_OPTIONS, offset, length);
#elif defined HAVE_SYS_FALLOCATE
	return syscall(SYS_fallocate, fd, DO_FALLOC_OPTIONS, (loff_t)offset, (loff_t)length);
#elif defined HAVE_EFFICIENT_POSIX_FALLOCATE
	return posix_fallocate(fd, offset, length);
#else
#error Coding error in SUPPORT_PREALLOCATION logic.
#endif
}
#endif

int do_open_nofollow(const char *pathname, int flags)
{
#ifndef O_NOFOLLOW
	STRUCT_STAT f_st, l_st;
#endif
	int fd;

	if (flags != O_RDONLY) {
		RETURN_ERROR_IF(dry_run, 0);
		RETURN_ERROR_IF_RO_OR_LO;
#ifndef O_NOFOLLOW
		/* This function doesn't support write attempts w/o O_NOFOLLOW. */
		errno = EINVAL;
		return -1;
#endif
	}

#ifdef O_NOFOLLOW
	fd = open(pathname, flags|O_NOFOLLOW);
#else
	if (do_lstat(pathname, &l_st) < 0)
		return -1;
	if (S_ISLNK(l_st.st_mode)) {
		errno = ELOOP;
		return -1;
	}
	if ((fd = open(pathname, flags)) < 0)
		return fd;
	if (do_fstat(fd, &f_st) < 0) {
	  close_and_return_error:
		{
			int save_errno = errno;
			close(fd);
			errno = save_errno;
		}
		return -1;
	}
	if (l_st.st_dev != f_st.st_dev || l_st.st_ino != f_st.st_ino) {
		errno = EINVAL;
		goto close_and_return_error;
	}
#endif

	return fd;
}
