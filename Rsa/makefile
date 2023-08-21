LDLIBS += -L.. -lcrypto
CFLAGS += -I../include/crypto

all: rsa_test

xeculid_test: rsa_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LDLIBS) -o $@ $<

clean:
	rm -f rsa_test *.o