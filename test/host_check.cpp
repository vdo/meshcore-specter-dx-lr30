// Host-side self-check for the pure (hardware-free) security logic:
//   - acl_add(): evicts the least-recently-active non-admin when full
//   - mesh_mac_then_decrypt(): refuses ciphertext larger than dest (S1 overflow)
// Run:  test/run_host_check.sh
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/acl.h"
#include "../src/meshcrypto/meshcrypto.h"

static void pub(uint8_t* p, uint8_t tag) { memset(p, 0, 32); p[0] = tag; p[1] = 0xAA; }

static void test_acl_eviction() {
    acl_clear();
    uint8_t p[32];
    // fill: one admin (oldest), three guests
    for (int i = 0; i < ACL_MAX; i++) {
        pub(p, (uint8_t)(i + 1));
        AclEntry* e = acl_add(p);
        assert(e && e->active && e->last_ts == 0);
        e->perms = (i == 0) ? PERM_ADMIN : PERM_READ;
        e->last_activity_ms = 100 + (uint32_t)i;   // entry 1 (admin) is the oldest
    }
    assert(acl_count() == ACL_MAX);
    // existing key → same entry, not evicted
    pub(p, 3);
    assert(acl_add(p) == acl_by_pub(p));
    // new key → evicts the oldest NON-admin (tag 2), keeps the admin (tag 1)
    pub(p, 9);
    AclEntry* n = acl_add(p);
    assert(n && n->pub[0] == 9 && n->last_ts == 0 && n->perms == 0);
    pub(p, 1); assert(acl_by_pub(p));    // admin kept
    pub(p, 2); assert(!acl_by_pub(p));   // oldest guest evicted
}

static void test_decrypt_bound() {
    uint8_t secret[32]; for (int i = 0; i < 32; i++) secret[i] = (uint8_t)i;
    uint8_t plain[208]; memset(plain, 'A', sizeof(plain));
    uint8_t wire[2 + 208];
    int wlen = mesh_encrypt_then_mac(secret, wire, plain, sizeof(plain));   // 2 + 208
    uint8_t dest[160 + 16];
    memset(dest, 0x5C, sizeof(dest));
    assert(mesh_mac_then_decrypt(secret, dest, 160, wire, wlen) == 0);       // too big → refused
    for (size_t i = 0; i < sizeof(dest); i++) assert(dest[i] == 0x5C);       // nothing written
    uint8_t big[208];
    assert(mesh_mac_then_decrypt(secret, big, 208, wire, wlen) == 208);       // fits → ok
    assert(memcmp(big, plain, 208) == 0);
    wire[0] ^= 1;                                                             // bad MAC
    assert(mesh_mac_then_decrypt(secret, big, 208, wire, wlen) == 0);
}

int main() {
    test_acl_eviction();
    test_decrypt_bound();
    puts("host_check: OK");
    return 0;
}
