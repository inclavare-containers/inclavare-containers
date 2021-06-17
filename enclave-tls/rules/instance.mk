# rules/instance.mk
#

ifneq ($(__Build_Env_Imported),1)
  $(error "Please import build_env.mk first!")
endif

ifeq ($(Enclave_Tls_Instance_Name),)
  $(error "Please set Enclave_Tls_Instance_Name used to specify the instance name!")
endif

ifeq ($(Enclave_Tls_Instance_Type),)
  $(error "Please set Enclave_Tls_Instance_Type used to specify the instance type!")
endif

# Decide whether to compile the complete untrusted application plus enclave image
# or just the trusted static library.
ifeq ($(App_Name),)
  App_Name := $(subst -,_,$(Enclave_Tls_Instance_Name))
  no_app := 1
endif

base_files := $(addsuffix .c,main pre_init init cleanup)
ifeq ($(Enclave_Tls_Instance_Type),crypto-wrapper)
  instance_files := $(addsuffix .c,gen_privkey gen_pubkey_hash gen_cert)
else ifeq ($(Enclave_Tls_Instance_Type), tls-wrapper)
  instance_files := $(addsuffix .c,negotiate receive transmit use_cert use_privkey)
else ifeq ($(Enclave_Tls_Instance_Type), attester)
  instance_files := $(addsuffix .c,collect_evidence)
else ifeq ($(Enclave_Tls_Instance_Type), verifier)
  instance_files := $(addsuffix .c,verify_evidence)
else ifeq ($(Enclave_Tls_Instance_Type), enclave-tls)
  instance_files :=
else
  $(error "Unsupported instance type '$(Enclave_Tls_Instance_Type)'")
endif

ifneq ($(Enclave_Tls_Instance_Type), enclave-tls)
instance_files += $(Enclave_Tls_Instance_Extra_Files) $(base_files)
instance_objs := $(instance_files:.c=.o)
endif

instance_cflags := \
  $(CFLAGS) -I$(Enclave_Tls_Incdir)
ifeq ($(Sgx_Enclave),1)
  # The objects of instance requre the header files from Intel SGX SDK
  instance_cflags += $(App_Cflags)
endif
ifeq ($(Tls_Wolfssl),1)
  # Search wolfssl header files from build directory
  instance_cflags += $(Wolfssl_Cflags) -I$(Build_Incdir)
endif
ifeq ($(Tls_Openssl),1)
  instance_cflags +=
  Enclave_Tls_Extra_Ldflags += $(Openssl_Ldflags)
endif

$(Topdir)/samples/sgx-stub-enclave/sgx_stub_u.o:
	make -C $(Topdir)/samples/sgx-stub-enclave

$(instance_objs): %.o: %.c
	$(CC) -c $(instance_cflags) -o $@ $<

$(Build_Libdir)/libenclave_tls.so:
	make -C $(Enclave_Tls_Srcdir) $(Build_Libdir)/libenclave_tls.so

instance_lib := \
  lib$(subst -,_,$(Enclave_Tls_Instance_Type))_$(subst -,_,$(Enclave_Tls_Instance_Name)).so
dest := $(Enclave_Tls_Libdir)/$(Enclave_Tls_Instance_Type)s/$(instance_lib)
install: $(Targets)
	$(INSTALL) -d -m 0755 $(dir $(dest))
	$(INSTALL) -m 0755 $(Targets) $(dest)
	make -C $(Enclave_Tls_Srcdir) install_libenclave_tls

uninstall:
	@rm -f $(dest)

mrproper:

# All instances always depend on libenclave_tls.so
#Dependencies += $(Build_Libdir)/libenclave_tls.so
ifeq ($(Sgx_Enclave),1)
  #Dependencies := $(App_Name)_u.o $(Dependencies)
  #Dependencies := $(Topdir)/samples/sgx-stub-enclave/sgx_stub_u.o $(Dependencies)
  ifeq ($(Tls_Wolfssl),1)
    # Provide wolfssl header files for $(App_Name)_u.[ch]
    #Dependencies := $(Build_Libdir)/libwolfssl_sgx.a $(Dependencies)
    Build_Instance_Dependencies := $(Build_Libdir)/libwolfssl_sgx.a
  endif
  ifndef OCCLUM
    Build_Instance_Dependencies += $(Topdir)/samples/sgx-stub-enclave/sgx_stub_u.o
  endif
endif
ifeq ($(Tls_Wolfssl),1)
  Build_Instance_Dependencies += $(Build_Libdir)/libwolfssl.so
endif
# All instances always depend on libenclave_tls.so
Build_Instance_Dependencies += $(Build_Libdir)/libenclave_tls.so

# TODO: abstract the build command into a variable
target := $(Build_Libdir)/$(Enclave_Tls_Instance_Type)s/$(instance_lib)
#$(target): $(Dependencies) $(instance_objs)
$(target): $(Build_Instance_Dependencies) $(instance_objs)
	$(INSTALL) -d -m 0755 $(dir $@)
	$(LD) $(Enclave_Tls_Ldflags) -soname=$(notdir $@).$(Major_Version) -o $@ $^ $(Enclave_Tls_Extra_Ldflags)

Build_Instance: $(target)

Targets += Build_Instance
Extra_Phonies += Build_Instance
Cleans += $(target) $(instance_objs)
