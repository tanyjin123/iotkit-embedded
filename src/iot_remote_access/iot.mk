TARGET     := RemoteTerminalDaemon

SRCS :=		src/connectivity/*.c	 
SRCS +=		src/core/*.c	 
SRCS +=	 	src/utility/hash_table/*.c	
SRCS +=	 	src/utility/json/*.c	
SRCS +=	 	src/utility/log/*.c	
SRCS +=	 	src/utility/misc/*.c	
SRCS +=	 	src/utility/sha256/*.c	

# CFLAGS +=	-Isrc/connectivity/
# CFLAGS +=	-Isrc/core/
# CFLAGS +=	-Isrc/utility/hash_table/
# CFLAGS +=	-Isrc/utility/json/
# CFLAGS +=	-Isrc/utility/log/
# CFLAGS +=	-Isrc/utility/misc/
# CFLAGS +=	-Isrc/utility/sha256/

LDFLAGS += -lnopoll
LDFLAGS += -lssl
LDFLAGS += -lcrypto
LDFLAGS += -lpthread
LDFLAGS += -ldl


