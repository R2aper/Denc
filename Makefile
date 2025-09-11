CC = gcc
FLAGS = -Wall -Wextra -pedantic -std=c11 -Iinclude
DEBUG_FLAG = -g 
LING_FLAG = -lestd -lpthread
OPTIMIZE_FLAG = -O3

NAME = denc

SRC_DIR = src
BUILD_DIR = build

SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst ${SRC_DIR}/%.c, ${BUILD_DIR}/%.o, $(SRC))

ifeq ($(debug),1)
	FLAGS += $(DEBUG_FLAG)
endif

ifeq ($(optimize),1)
	FLAGS += $(OPTIMIZE_FLAG)
endif

.PHONY: all clean

all: dir ${NAME}

${NAME}: ${OBJ}
	${CC} ${FLAGS} $^ -o $@ $(LING_FLAG)

${BUILD_DIR}/%.o : $(SRC_DIR)/%.c
	${CC} ${FLAGS} -c $< -o $@

dir: 
	mkdir -p ${BUILD_DIR}
	
clean: 
	rm -rf ${BUILD_DIR}
	rm -f ${NAME}

