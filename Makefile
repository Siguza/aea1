SRC                 := src

META                := aea1meta
META_C              := meta.c
META_H     	        :=
META_CC_FLAGS       := -std=c99 -Wall -O3 -flto
META_LD_FLAGS       :=
META_LD_LIBS        :=
ifdef HPKE
    META_C          += cJSON.c
    META_H          += cJSON.h
    META_CC_FLAGS   += -DWITH_HPKE=1
    META_LD_LIBS    += -lcurl
ifdef OPENSSL
    META_CC_FLAGS   += -DWITH_OPENSSL=1
    META_LD_LIBS    += -lcrypto
endif
endif
META_C              := $(addprefix $(SRC)/,$(META_C))
META_H              := $(addprefix $(SRC)/,$(META_H))

ALL                 := $(META)


.PHONY: all clean

all: $(ALL)

$(META): $(META_C) $(META_H)
	$(CC) -o $@ $(META_C) $(META_CC_FLAGS) $(CFLAGS) $(META_LD_FLAGS) $(LDFLAGS) $(META_LD_LIBS) $(LIBS)

clean:
	rm -f $(META)
