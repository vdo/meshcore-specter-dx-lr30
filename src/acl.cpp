#include "acl.h"
#include <string.h>

static AclEntry entries[ACL_MAX];

AclEntry* acl_by_pub(const uint8_t* pub) {
    for (int i = 0; i < ACL_MAX; i++)
        if (entries[i].active && memcmp(entries[i].pub, pub, ACL_PUBKEY) == 0)
            return &entries[i];
    return 0;
}

AclEntry* acl_add(const uint8_t* pub) {
    AclEntry* e = acl_by_pub(pub);
    if (e) return e;
    AclEntry* victim = 0;
    for (int i = 0; i < ACL_MAX; i++) {
        AclEntry* c = &entries[i];
        if (!c->active) { victim = c; break; }
        // prefer the oldest non-admin; fall back to the oldest admin
        bool c_better = !victim
            || (victim->perms == PERM_ADMIN && c->perms != PERM_ADMIN)
            || ((victim->perms == PERM_ADMIN) == (c->perms == PERM_ADMIN)
                && (int32_t)(c->last_activity_ms - victim->last_activity_ms) < 0);
        if (c_better) victim = c;
    }
    memset(victim, 0, sizeof(*victim));
    memcpy(victim->pub, pub, ACL_PUBKEY);
    victim->active = 1;
    return victim;
}

void acl_remove_pub(const uint8_t* pub) {
    AclEntry* e = acl_by_pub(pub);
    if (e) e->active = 0;
}

void acl_clear(void) {
    for (int i = 0; i < ACL_MAX; i++) entries[i].active = 0;
}

int acl_count(void) {
    int c = 0;
    for (int i = 0; i < ACL_MAX; i++) if (entries[i].active) c++;
    return c;
}

const AclEntry* acl_at(int i) {
    return (i >= 0 && i < ACL_MAX) ? &entries[i] : 0;
}
