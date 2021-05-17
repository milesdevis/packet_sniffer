# https://spin.atomicobject.com/2016/08/26/makefile-c-projects/

TARGET := sniffer
OBJ_DIR := obj

SRCS := sniffer.c ethernet.c ip.c udp.c util.c
OBJS := $(SRCS:%=$(OBJ_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

CC ?= clang
CXX ?= clang++
CPPFLAGS ?= -I. -MMD -MP
LDFLAGS ?= -lpcap

GREEN := \e[32m
NC := \e[0m

$(TARGET): $(OBJS)
	@echo "$(GREEN)Linking Target $@$(NC)"
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.c.o: %.c
	@echo "[CC] $@"
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.cpp.o: %.cpp
	@echo "[CXX] $@"
	@mkdir -p $(dir $@)
	@$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -r $(OBJ_DIR) $(TARGET)

-include $(DEPS)
