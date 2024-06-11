TARGET = aea1meta
SRC    = src

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)/*.c
	$(CC) -o $@ $(SRC)/*.c -std=c11 -Wall -O3 $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
