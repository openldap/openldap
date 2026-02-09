/*
 * Fuzz LDAP Distinguished Name (DN) parsing (RFC 4514).
 *
 * Standalone parser for LDAP DNs: attribute type+value pairs, multi-valued
 * RDNs, escaped characters, hex-encoded values, quoted strings, OID types.
 *
 * Build:
 *   clang -g -fsanitize=fuzzer,address fuzz_ldap_dn.c -o fuzz_ldap_dn
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_RDN_COMPONENTS 64
#define MAX_AVA_LEN 512

typedef struct { char type[MAX_AVA_LEN]; char value[MAX_AVA_LEN]; int hex_encoded; } AVA;
typedef struct { AVA components[4]; int num_components; } RDN;
typedef struct { RDN rdns[MAX_RDN_COMPONENTS]; int num_rdns; } DN;

static int parse_hex_value(const char *s, size_t len, char *out, size_t out_max) {
  if (len < 1 || s[0] != '#') return -1;
  size_t out_pos = 0, i = 1;
  while (i + 1 < len && out_pos < out_max - 1) {
    int h = -1, l = -1;
    if (s[i] >= '0' && s[i] <= '9') h = s[i] - '0'; else if (s[i] >= 'a' && s[i] <= 'f') h = s[i] - 'a' + 10; else if (s[i] >= 'A' && s[i] <= 'F') h = s[i] - 'A' + 10;
    if (s[i+1] >= '0' && s[i+1] <= '9') l = s[i+1] - '0'; else if (s[i+1] >= 'a' && s[i+1] <= 'f') l = s[i+1] - 'a' + 10; else if (s[i+1] >= 'A' && s[i+1] <= 'F') l = s[i+1] - 'A' + 10;
    if (h < 0 || l < 0) return -1;
    out[out_pos++] = (char)((h << 4) | l); i += 2;
  }
  out[out_pos] = '\0'; return (int)out_pos;
}

static size_t parse_attr_type(const char *s, size_t len, char *out, size_t out_max) {
  size_t i = 0, out_pos = 0;
  while (i < len && (s[i] == ' ' || s[i] == '\t')) i++;
  while (i < len && out_pos < out_max - 1) {
    char c = s[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') { out[out_pos++] = c; i++; } else break;
  }
  out[out_pos] = '\0'; return i;
}

static int parse_dn(const char *s, size_t len, DN *dn) {
  dn->num_rdns = 0;
  if (len == 0) return 0;
  size_t i = 0;
  while (i < len && dn->num_rdns < MAX_RDN_COMPONENTS) {
    RDN *rdn = &dn->rdns[dn->num_rdns]; rdn->num_components = 0;
    do {
      if (rdn->num_components >= 4) break;
      AVA *ava = &rdn->components[rdn->num_components]; memset(ava, 0, sizeof(*ava));
      while (i < len && (s[i] == ' ' || s[i] == '\t')) i++;
      i += parse_attr_type(s + i, len - i, ava->type, MAX_AVA_LEN);
      while (i < len && s[i] == ' ') i++;
      if (i < len && s[i] == '=') i++;
      while (i < len && s[i] == ' ') i++;
      if (i < len && s[i] == '#') {
        size_t vs = i; i++;
        while (i < len && ((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')||(s[i]>='A'&&s[i]<='F'))) i++;
        parse_hex_value(s + vs, i - vs, ava->value, MAX_AVA_LEN); ava->hex_encoded = 1;
      } else {
        size_t vp = 0;
        while (i < len && s[i] != ',' && s[i] != '+' && s[i] != ';' && vp < MAX_AVA_LEN - 1) {
          if (s[i] == '\\' && i + 1 < len) { i++; ava->value[vp++] = s[i]; } else { ava->value[vp++] = s[i]; }
          i++;
        }
        ava->value[vp] = '\0';
      }
      rdn->num_components++;
    } while (i < len && s[i] == '+' && ++i);
    dn->num_rdns++;
    if (i < len && (s[i] == ',' || s[i] == ';')) i++; else break;
  }
  return dn->num_rdns;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 4096) return 0;
  char *str = (char *)malloc(size + 1);
  if (!str) return 0;
  memcpy(str, data, size); str[size] = '\0';
  DN dn; parse_dn(str, size, &dn);
  free(str);
  return 0;
}
