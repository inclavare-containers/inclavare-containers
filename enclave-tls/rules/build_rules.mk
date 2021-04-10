# rules/build_rules.mk
#

ifneq ($(__Build_Env_Imported),1)
  $(error "Please import build_env.mk first!")
endif

ifeq ($(Targets),)
  $(warning "Please set Targets used to specify the build targets!")
endif

.PHONY: all clean install uninstall config mrproper FORCE $(Extra_Phonies)

all: $(Targets)

clean:
	@for d in $(Clean_Dirs); do \
	  make -C $$d $@; \
	done
	@rm -rf $(Cleans)

FORCE:
