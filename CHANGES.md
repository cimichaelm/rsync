
2015/06/14	NEW FEATURE: File locking
		Added read file locking and checking to allow
		copying of files that are being updated with
		a compatible fctl advisory locking scheme.

		Michael Moscovitch
		CiteNet Internet / Pathway Communications

New configure option:
 --enable-locking        enable file locking checks with fctl

New runtime options:
     --skipreadlock          skip files that locked
     --no-skipreadlock       do not skip files that locked (default)
     --waitreadlock          wait on locked files
     --no-waitreadlock       do not wait on locked files (default)

This feature is in beta test status.
Aside from an extra function call, the behavior is not changed if the options
are not specified on the command line.

To use you must build the source with the feature enabled.


./configure --enable-locking
make

