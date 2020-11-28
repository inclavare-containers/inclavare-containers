OUTPUT ?= ./
HOST_CFLAGS := -Wall -Werror -g -fPIC -z noexecstack \
	       -Wno-unused-const-variable -std=gnu11
HOST_LDFLAGS := -fPIC -shared -Wl,-Bsymbolic

$(OUTPUT)/libpal_ne.so: $(OUTPUT)/ne.o $(OUTPUT)/pal_ne.o
	$(CC) $(HOST_LDFLAGS) -o $@ $^ -lprotobuf-c -lutil -lpthread

$(OUTPUT)/pal_ne.o: pal_ne.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/ne.o: ne.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

EXTRA_CLEAN := \
	$(OUTPUT)/ne.o \
	$(OUTPUT)/pal_ne.o \
	$(OUTPUT)/libpal_ne.so

clean:
	rm -f ${EXTRA_CLEAN}

.PHONY: clean all
