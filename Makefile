APXS     = $(shell PATH=$$PATH:/usr/local/apache/bin which apxs)

NAME     = mod_rbld
SRC	 = $(NAME).c
BINARIES = $(NAME).o $(NAME).so $(NAME).la 
SBINDIR  = $(shell $(APXS) -q SBINDIR)

all: $(BINARIES)

$(NAME).o: $(SRC)
	$(APXS) -c $(SRC) 

$(NAME).so: $(NAME).o

$(NAME).la: $(NAME).so

clean:
	rm -rf *.so *.o *.slo *.la *.lo .libs

install: $(BINARIES)
	$(APXS) -i $(NAME).la
