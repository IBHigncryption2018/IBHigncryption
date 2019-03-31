#ifndef _PBC_CONTEXT_H
#define _PBC_CONTEXT_H
#ifdef __cplusplus
extern "C" {
#endif

typedef struct pbc_context_s {
  pairing_t pairing;
  element_t mk;
} pbc_context_t;

#ifdef __cplusplus
}
#endif
#endif // PBC_CONTEXT_H
