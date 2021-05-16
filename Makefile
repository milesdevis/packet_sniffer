# https://spin.atomicobject.com/2016/08/26/makefile-c-projects/

TARGET := sniffer
OBJ_DIR := obj

SRC := sniffer.c ethernet.c
OBJ := $(SRC:%=obj/%.o)
DEP := $(OBJ:.o=.d)

CC ?= clang
CPPFLAGS ?= -I. -MMD -MP
LDFLAGS ?= -lpcap

GREEN := \e[32m
NC := \e[0m

$(TARGET): $(OBJ)
	@echo "$(GREEN)Linking Target $@$(NC)"
	@$(CC) $(OBJ) -o $@ $(LDFLAGS)

obj/%.c.o: %.c
	@echo "[CC] $@"
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

obj/%.cpp.o: %.cpp
	@echo "[CC] $@"
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -r $(OBJ_DIR) $(TARGET)

-include $(DEP)