CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
TARGET = forth
SRC = forth.c
INSTALL_DIR = $(HOME)/scripts

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

install: $(TARGET)
	make
	mkdir -p $(INSTALL_DIR)
	cp $(TARGET) $(INSTALL_DIR)/$(TARGET)
	chmod +x $(INSTALL_DIR)/$(TARGET)

clean:
	rm -f $(TARGET)

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)

.PHONY: all install clean uninstall
