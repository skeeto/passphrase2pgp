CFLAGS = -ansi -W -Wall -Wextra -ggdb -O0
LDLIBS = -lgcrypt -lgmp

passphrase2pgp : passphrase2pgp.c

.PHONY : run clean

run : passphrase2pgp
	./$^

clean :
	$(RM) passphrase2pgp
