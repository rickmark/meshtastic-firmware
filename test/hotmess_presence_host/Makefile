# Host build of the Hot Mess presence core. `make` runs the self-checks and writes vectors.json,
# the shared test vectors the AudienceKit Ruby verifier asserts against.
CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -DHMP_HOST_TEST -Wno-deprecated-declarations
SRC = ../../src/modules/optional/HotMessPresence/PresenceCore.cpp crypto_openssl.cpp vectors.cpp

vectors.json: hmp_vectors
	./hmp_vectors > vectors.json

hmp_vectors: $(SRC) ../../src/modules/optional/HotMessPresence/PresenceCore.h
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) -lcrypto

clean:
	rm -f hmp_vectors vectors.json
.PHONY: clean
