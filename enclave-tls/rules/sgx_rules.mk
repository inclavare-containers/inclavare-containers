# rules/sgx_rules.mk
#
# The following variables are required as the inputs.
#
# - App(REQUIRED): specify the output filename of untrusted application
# - App_C_Files (REQUIRED): the C source files for application
# - App_Cxx_Files (REQUIRED): the C++ source files for application
# - App_Extra_Incdir (OPTIONAL): the extra include paths for header files used by application
# - Enclave_C_Files (REQUIRED): the C source files for enclave
# - Enclave_Cxx_Files (REQUIRED): the C++ source files for enclave
# - Enclave_Extra_Incdir (OPTIONAL): the extra include paths for header files used by enclave
# - SGX_DEBUG (OPTIONAL): This is the default.
# - SGX_PRERELEASE (OPTIONAL):
# - SGX_MODE (OPTIONAL):
# - SGX_ARCH (OPTIONAL):
#
# In addition, the caller must prepare well the following input materials:
# - $(App_Name)_enclave.xml: the enclave configiration file
# - $(App_Name)_enclave.lds: the enclave linker script file
# - $(App_Name)_enclave.pem: the enclave signing key file
# - $(App_Name).edl: the EDL file for the definitions of ECALLs and OCALLs
#
# The resulting outputs include:
# - $(App_Name): the output application binary
# - $(App_Name)_enclave.so: the output unsigned enclave image
# - $(App_Name)_enclave.signed.so: the output signed enclave image

ifneq ($(__Build_Env_Imported),1)
  $(error "Please import build_env.mk first!")
endif

ifneq ($(__Sgx_Env_Imported),1)
  $(error "Please import sgx_env.mk first!")
endif

ifeq ($(no_app),1)
  ifneq ($(Enclave_Static_Lib_Name),)
    enclave_static_lib := lib$(subst -,_,$(Enclave_Tls_Instance_Type))_$(Enclave_Static_Lib_Name).a
  endif
endif

ifneq ($(no_app),1)
  ifeq ($(shell [ -f $(enclave_config_file) ] && echo 1),)
    $(error "The enclave configuration file $(enclave_config_file) is unavailable")
  else ifeq ($(shell [ -f $(enclave_linker_script) ] && echo 1),)
    $(error "The enclave linker script file $(enclave_linker_script) is unavailable")
  else ifeq ($(shell [ -f $(enclave_signing_key) ] && echo 1),)
    $(error "The enclave signing key file $(enclave_signing_key) is unavailable")
  endif
endif

ifeq ($(shell [ -f $(app_edl) ] && echo 1),)
  $(error "The EDL file $(app_edl) is unavailable")
endif

ifeq (0,1)
ifneq ($(no_app),1)
  ifeq ($(Enclave_C_Files),)
    ifeq ($(Enclave_Cxx_Files),)
      $(error "Please define either Enclave_C_Files or Enclave_Cxx_Files for your enclave C/C++ source files")
    endif
  endif
  ifeq ($(App_C_Files),)
    ifeq ($(App_Cxx_Files),)
      $(error "Please define either App_C_Files or App_Cxx_Files for your application C/C++ source files")
    endif
  endif
endif
endif

sgx_enclave_signer := $(SGX_SDK)/bin/$(SGX_ARCH)/sgx_sign
signed_enclave := $(enclave_name).signed.so
unsigned_enclave := $(enclave_name).so
$(signed_enclave): $(unsigned_enclave)
ifeq ($(build_mode),HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(build_mode),SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(build_mode),HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(build_mode),SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else ifeq ($(build_mode),HW_RELEASE)
	@echo "The project has been built in release hardware mode."
else ifeq ($(build_mode),SIM_RELEASE)
	@echo "The project has been built in release simulation mode."
else
	$(error "Unknown build mode.")
endif
	$(sgx_enclave_signer) sign -key $(enclave_signing_key) -enclave $< \
	  -out $@ -config $(enclave_config_file)
	@echo "SIGN =>  $@"

enclave_cxx_objs := $(sort $(Enclave_Cxx_Files:.cpp=.o))
enclave_c_objs := $(sort $(Enclave_C_Files:.c=.o))
$(Build_Libdir)/$(enclave_static_lib): $(enclave_cxx_objs) $(enclave_c_objs)
	$(AR) rcs $@ $^
	@echo "LINK =>  $@"

$(unsigned_enclave): $(App_Name)_t.o $(Enclave_Static_Lib)
	$(CXX) $(Enclave_Cxxflags) $^ -o $@ $(Enclave_Ldflags)
#	$(CXX) $(sgx_common_cxxflags) $(enclave_ldflags) $^ -o $@
	@echo "LINK =>  $@"

ifeq ($(Tls_Wolfssl),1)
  Enclave_Cflags += $(Wolfssl_Sgx_Cflags)
endif
# Add macro HAVE_TM_TYPE to avoid compiling error about struct tm re-definition
$(App_Name)_t.o: $(App_Name)_t.c
	$(CC) $(Enclave_Cflags) -DHAVE_TM_TYPE -c $< -o $@
	@echo "CC   <=  $<"

$(App_Name)_t.c: $(App_Name)_t.h

sgx_edger8r := $(SGX_SDK)/bin/$(SGX_ARCH)/sgx_edger8r
$(App_Name)_t.h: $(app_edl) $(Build_Libdir)/libwolfssl_sgx.a
	$(sgx_edger8r) --trusted $< --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

ifeq ($(Tls_Wolfssl),1)
  Enclave_Cxxflags += $(Wolfssl_Sgx_Cflags)
endif
$(enclave_cxx_objs): %.o : %.cpp
	$(CXX) $(Enclave_Cxxflags) -c $< -o $@
	@echo "CXX  <=  $<"

# Add macro HAVE_TM_TYPE to avoid compiling error about struct tm re-definition
$(enclave_c_objs): %.o : %.c
	$(CC) $(Enclave_Cflags) -DHAVE_TM_TYPE -c $< -o $@
	@echo "CC   <=  $<"

app_cxx_objs := $(sort $(App_Cxx_Files:.cpp=.o))
app_c_objs := $(sort $(App_C_Files:.c=.o))

# The untrusted application is built only when setting App_Name by the caller explicitly.
ifneq ($(no_app),1)
$(App_Name): $(App_Name)_u.o $(app_cxx_objs) $(app_c_objs)
	$(CXX) $(App_Cxxflags) $(App_Ldflags) $^ -o $@
#	$(CXX) $(sgx_common_cxxflags) $(App_Ldflags) $^ -o $@
	@echo "LINK =>  $@"
endif

$(App_Name)_u.o: $(App_Name)_u.c
	$(CC) $(App_Cflags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Name)_u.c: $(App_Name)_u.h

$(App_Name)_u.h: $(app_edl) $(Build_Libdir)/libwolfssl_sgx.a
	$(sgx_edger8r) --untrusted $< --search-path $(SGX_SDK)/include
	$(sgx_edger8r) --trusted $< --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(app_cxx_objs): %.o : %.cpp
	$(CXX) $(App_Cxxflags) -c $^ -o $@
	@echo "CXX  <=  $<"

$(app_c_objs): %.o : %.c
	$(CC) $(App_Cflags) -c $^ -o $@
	@echo "CC   <=  $<"

$(Build_Libdir)/libwolfssl_sgx.a:
	make -C $(Topdir)/src/external/wolfssl

Cleans += \
  $(App_Name) $(unsigned_enclave) $(signed_enclave) \
  $(app_cxx_objs) $(app_c_objs) \
  $(enclave_cxx_objs) $(enclave_c_objs) \
  $(App_Name)_[ut].* \
  $(Enclave_Static_Lib)

ifneq ($(no_app),1)
  #Targets += $(App_Name) $(signed_enclave)
  Targets += $(App_Name)_t.o $(App_Name)_u.o $(Enclave_Static_Lib) $(signed_enclave)
else
  Targets += $(App_Name)_t.o $(App_Name)_u.o $(Build_Libdir)/$(enclave_static_lib)
  #Dependencies := $(App_Name)_u.o $(Dependencies)
endif
