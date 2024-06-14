#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define LE32(ptr) ((uint32_t)((ptr)[3]) << 24 | (uint32_t)((ptr)[2]) << 16 | (uint32_t)((ptr)[1]) << 8 | (uint32_t)((ptr)[0]))

#define WRAPPED_KEY_BASE64_LEN  0x40
#define WRAPPED_KEY_LEN         0x30
#define UNWRAPPED_KEY_LEN       0x20

typedef enum
{
    kActDump,
    kActList,
    kActValue,
#ifdef WITH_HPKE
    kActUnwrapKey,
#endif
} action_t;

static bool json_print_string(const char *buf, size_t len)
{
    putchar('"');
    for(size_t i = 0; i < len; ++i)
    {
        char ch = buf[i];
        switch(ch)
        {
            case '"':
            case '\\':
                putchar('\\');
                // fallthrough

            case ' ':
            case '!':
            case '#':
            case '$':
            case '%':
            case '&':
            case '\'':
            case '(':
            case ')':
            case '*':
            case '+':
            case ',':
            case '-':
            case '.':
            case '/':
            case ':':
            case ';':
            case '<':
            case '=':
            case '>':
            case '?':
            case '@':
            case '[':
            case ']':
            case '^':
            case '_':
            case '`':
            case '{':
            case '|':
            case '}':
            case '~':

            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':

            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
            case 'G':
            case 'H':
            case 'I':
            case 'J':
            case 'K':
            case 'L':
            case 'M':
            case 'N':
            case 'O':
            case 'P':
            case 'Q':
            case 'R':
            case 'S':
            case 'T':
            case 'U':
            case 'V':
            case 'W':
            case 'X':
            case 'Y':
            case 'Z':

            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
            case 'g':
            case 'h':
            case 'i':
            case 'j':
            case 'k':
            case 'l':
            case 'm':
            case 'n':
            case 'o':
            case 'p':
            case 'q':
            case 'r':
            case 's':
            case 't':
            case 'u':
            case 'v':
            case 'w':
            case 'x':
            case 'y':
            case 'z':
                putchar(ch);
                break;

            default:
                return false;
        }
    }
    putchar('"');
    return true;
}

#ifdef WITH_HPKE
#include <curl/curl.h>
#include "cJSON.h"

static char* read_file(const char *file)
{
    char *ret = NULL;
    FILE *f = fopen(file, "rb");
    if(!f)
    {
        fprintf(stderr, "Failed to open file %s: %s\n", file, strerror(errno));
        return NULL;
    }

    int r = fseeko(f, 0, SEEK_END);
    if(r == 0)
    {
        off_t end = ftello(f);
        if(end == -1)
        {
            fprintf(stderr, "ftell: %s\n", strerror(errno));
            goto out;
        }
        r = fseeko(f, 0, SEEK_SET);
        if(r != 0)
        {
            fprintf(stderr, "fseek: %s\n", strerror(errno));
            goto out;
        }
        ret = malloc(end + 1);
        if(!ret)
        {
            fprintf(stderr, "malloc: %s\n", strerror(errno));
            goto out;
        }
        if(fread(ret, end, 1, f) != 1)
        {
            fprintf(stderr, "fread: %s\n", strerror(errno));
            free(ret);
            ret = NULL;
            goto out;
        }
        ret[end] = '\0';
    }
    else
    {
        size_t sz = 0x100;
        size_t len = 0;
        for(; ; sz *= 2)
        {
            void *tmp = realloc(ret, sz);
            if(!tmp)
            {
                fprintf(stderr, "realloc: %s\n", strerror(errno));
                free(ret);
                ret = NULL;
                goto out;
            }
            ret = tmp;

            size_t want = sz - len - 1;
            size_t have = fread(ret + len, 1, want, f);
            len += have;
            if(have < want)
            {
                if(feof(f))
                {
                    break;
                }
                fprintf(stderr, "fread: %s\n", strerror(errno));
                free(ret);
                ret = NULL;
                goto out;
            }
        }
        ret[len] = '\0';
    }

out:;
    fclose(f);
    return ret;
}

typedef struct
{
    char *buf;
    size_t len;
} body_t;

static size_t fetch_cb(char *ptr, size_t size, size_t nmemb, void *arg)
{
    size_t sz = size * nmemb;
    if(sz > 0)
    {
        body_t *body = arg;
        size_t len = body->len + sz;
        char *buf = realloc(body->buf, len);
        if(!buf)
        {
            fprintf(stderr, "realloc: %s\n", strerror(errno));
            return 0;
        }
        memcpy(buf + body->len, ptr, sz);
        body->buf = buf;
        body->len = len;
    }
    return sz;
}

static char* fetch(const char *url)
{
    char *ret = NULL;
    body_t body = {};
    CURL *curl = curl_easy_init();
    if(!curl)
    {
        fprintf(stderr, "curl_easy_init failed\n");
        return NULL;
    }

    CURLcode c = curl_easy_setopt(curl, CURLOPT_URL, url);
    if(c != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_setopt(CURLOPT_URL): %s\n", curl_easy_strerror(c));
        goto out;
    }
    c = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    if(c != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_setopt(CURLOPT_FOLLOWLOCATION): %s\n", curl_easy_strerror(c));
        goto out;
    }
    c = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetch_cb);
    if(c != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_setopt(CURLOPT_WRITEFUNCTION): %s\n", curl_easy_strerror(c));
        goto out;
    }
    c = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    if(c != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_setopt(CURLOPT_WRITEDATA): %s\n", curl_easy_strerror(c));
        goto out;
    }

    c = curl_easy_perform(curl);
    if(c != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_perform: %s\n", curl_easy_strerror(c));
        goto out;
    }

    long status = 0;
    c = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if(c != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_perform: %s\n", curl_easy_strerror(c));
        goto out;
    }

    if(status != 200)
    {
        fprintf(stderr, "HTTP status %lu (%s)\n", status, url);
        goto out;
    }

    size_t len = strnlen(body.buf, body.len);
    if(len != body.len)
    {
        fprintf(stderr, "Server response contains NUL bytes.\n");
        goto out;
    }

    ret = malloc(len + 1);
    if(!ret)
    {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        goto out;
    }
    memcpy(ret, body.buf, len);
    ret[len] = '\0';

out:;
    if(body.buf) free(body.buf);
    curl_easy_cleanup(curl);
    return ret;
}

static bool extract_hpke_fields(const char *hpkeData, char **encRequest, char **wrappedKey)
{
    cJSON *dict = cJSON_Parse(hpkeData);
    if(!cJSON_IsObject(dict))
    {
        fprintf(stderr, "HPKE data is not a valid JSON object.\n");
        cJSON_Delete(dict);
        return false;
    }

    cJSON *encStr = cJSON_GetObjectItemCaseSensitive(dict, "enc-request");
    if(!cJSON_IsString(encStr) || !encStr->valuestring)
    {
        fprintf(stderr, "Failed to get enc-request.\n");
        cJSON_Delete(dict);
        return false;
    }

    cJSON *keyStr = cJSON_GetObjectItemCaseSensitive(dict, "wrapped-key");
    if(!cJSON_IsString(keyStr) || !keyStr->valuestring)
    {
        fprintf(stderr, "Failed to get wrapped-key.\n");
        cJSON_Delete(dict);
        return false;
    }

    if(!(*encRequest = strdup(encStr->valuestring)))
    {
        fprintf(stderr, "strdup(enc-request): %s\n", strerror(errno));
        cJSON_Delete(dict);
        return false;
    }

    if(!(*wrappedKey = strdup(keyStr->valuestring)))
    {
        fprintf(stderr, "strdup(enc-request): %s\n", strerror(errno));
        cJSON_Delete(dict);
        return false;
    }

    cJSON_Delete(dict);
    return true;
}

static uint8_t b64d_table(char ch)
{
    switch(ch)
    {
        case 'A': return 0x00;
        case 'B': return 0x01;
        case 'C': return 0x02;
        case 'D': return 0x03;
        case 'E': return 0x04;
        case 'F': return 0x05;
        case 'G': return 0x06;
        case 'H': return 0x07;
        case 'I': return 0x08;
        case 'J': return 0x09;
        case 'K': return 0x0a;
        case 'L': return 0x0b;
        case 'M': return 0x0c;
        case 'N': return 0x0d;
        case 'O': return 0x0e;
        case 'P': return 0x0f;
        case 'Q': return 0x10;
        case 'R': return 0x11;
        case 'S': return 0x12;
        case 'T': return 0x13;
        case 'U': return 0x14;
        case 'V': return 0x15;
        case 'W': return 0x16;
        case 'X': return 0x17;
        case 'Y': return 0x18;
        case 'Z': return 0x19;
        case 'a': return 0x1a;
        case 'b': return 0x1b;
        case 'c': return 0x1c;
        case 'd': return 0x1d;
        case 'e': return 0x1e;
        case 'f': return 0x1f;
        case 'g': return 0x20;
        case 'h': return 0x21;
        case 'i': return 0x22;
        case 'j': return 0x23;
        case 'k': return 0x24;
        case 'l': return 0x25;
        case 'm': return 0x26;
        case 'n': return 0x27;
        case 'o': return 0x28;
        case 'p': return 0x29;
        case 'q': return 0x2a;
        case 'r': return 0x2b;
        case 's': return 0x2c;
        case 't': return 0x2d;
        case 'u': return 0x2e;
        case 'v': return 0x2f;
        case 'w': return 0x30;
        case 'x': return 0x31;
        case 'y': return 0x32;
        case 'z': return 0x33;
        case '0': return 0x34;
        case '1': return 0x35;
        case '2': return 0x36;
        case '3': return 0x37;
        case '4': return 0x38;
        case '5': return 0x39;
        case '6': return 0x3a;
        case '7': return 0x3b;
        case '8': return 0x3c;
        case '9': return 0x3d;
        case '+': return 0x3e;
        case '/': return 0x3f;

        case '=': return 0x7f;
        default:  return 0xff;
    }
}

static bool b64d(char *buf, size_t *sz) // assumes multiple of 4
{
    size_t w = 0;
    for(size_t r = 0; buf[r] != '\0'; r += 4)
    {
        uint8_t bytes = 3;
        uint32_t v = 0;
        for(size_t i = 0; i < 4; ++i)
        {
            uint8_t u = b64d_table(buf[r+i]);
            if(u & 0x80)
            {
                return false;
            }
            else if(u & 0x40)
            {
                if(i < 2)
                {
                    return false;
                }
                else
                {
                    --bytes;
                }
            }
            else if(i == 3 && bytes < 3)
            {
                return false;
            }
            else
            {
                v |= (uint32_t)u << ((3 - i) * 6);
            }
        }
        for(uint8_t i = 0; i < bytes; ++i)
        {
            buf[w++] = (char)(uint8_t)((v >> ((2 - i) * 8)) & 0xff);
        }
    }
    *sz = w;
    return true;
}

static void b64p(const uint8_t *buf, size_t len)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint8_t bits = 0;
    uint16_t v = 0;
    for(size_t i = 0; i < len; ++i)
    {
        v = (v << 8) | buf[i];
        for(bits += 8; bits >= 6; bits -= 6)
        {
            putchar(table[(v >> (bits - 6)) & 0x3f]);
        }
    }
    if(bits > 0)
    {
        putchar(table[(v & ((1 << bits) - 1)) << (6 - bits)]);
        for(; bits < 6; bits += 2)
        {
            putchar('=');
        }
    }
}

#ifdef WITH_OPENSSL
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_MAJOR < 3 || OPENSSL_VERSION_MINOR < 2
#   error OpenSSL before version 3.2 does not support HPKE.
#endif
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/pem.h>

static bool hpke_receive(const char *pem, const void *enc, size_t enclen, void *wrappedKey)
{
    bool ret = false;
    BIO *bio = NULL;
    EVP_PKEY *key = NULL;
    OSSL_HPKE_CTX *ctx = NULL;

    bio = BIO_new_mem_buf(pem, -1);
    if(!bio)
    {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, 0);
    if(!key)
    {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    const OSSL_HPKE_SUITE suite = { OSSL_HPKE_KEM_ID_P256, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_256 };
    ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
    if(!ctx)
    {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    if(!OSSL_HPKE_decap(ctx, enc, enclen, key, NULL, 0))
    {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    uint8_t tmp[UNWRAPPED_KEY_LEN];
    size_t sz = sizeof(tmp);
    if(!OSSL_HPKE_open(ctx, tmp, &sz, NULL, 0, wrappedKey, WRAPPED_KEY_LEN))
    {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    if(sz != sizeof(tmp))
    {
        fprintf(stderr, "Decrypted key has wrong length: 0x%zx\n", sz);
        goto out;
    }

    memcpy(wrappedKey, tmp, sizeof(tmp));
    ret = true;

out:;
    if(ctx) OSSL_HPKE_CTX_free(ctx);
    if(key) EVP_PKEY_free(key);
    if(bio) BIO_vfree(bio);
    return ret;
}
#else /* WITH_OPENSSL */
#   error HPKE requires OpenSSL backend.
#endif /* WITH_OPENSSL */
#endif /* WITH_HPKE */

int main(int argc, const char **argv)
{
    action_t act = kActDump;
    int aoff = 1;
    if(aoff < argc && argv[aoff][0] == '-')
    {
        char opt;
        if((opt = argv[aoff][1]) == '\0' || argv[aoff][2] != '\0')
        {
            fprintf(stderr, "Bad option: -%s\n", &argv[aoff][1]);
            return -1;
        }
        switch(opt)
        {
            case '-':
                break;

            case 'k':
#ifdef WITH_HPKE
                act = kActUnwrapKey;
                break;
#else
                fprintf(stderr, "Feature not enabled.\n");
                return -1;
#endif

            case 'l':
                act = kActList;
                break;

            default:
                fprintf(stderr, "Unknown option: -%c\n", opt);
                return -1;
        }
        ++aoff;
    }

    if(argc - aoff < 1 || argc - aoff > 2)
    {
        fprintf(stderr, "Usage:\n"
                        "    %s file.aea              - Dump all props as JSON\n"
                        "    %s file.aea [prop]       - Dump single prop value raw\n"
                        "    %s -l file.aea           - Dump prop names, one per line\n"
#ifdef WITH_HPKE
                        "    %s -k file.aea [key.pem] - Print archive decryption key\n"
                        , argv[0]
#endif
                        , argv[0], argv[0], argv[0]);
        return 1;
    }

    const char *infile = argv[aoff];
    const char *prop = NULL;
#ifdef WITH_HPKE
    const char *keyfile = NULL;
#endif
    if(argc - aoff > 1)
    {
        switch(act)
        {
            case kActDump:
                act = kActValue;
                prop = argv[aoff + 1];
                break;

#ifdef WITH_HPKE
            case kActUnwrapKey:
                keyfile = argv[aoff + 1];
                break;
#endif

            default:
                fprintf(stderr, "Conflicting arguments given.\n");
                return -1;
        }
    }

    FILE *aea = fopen(infile, "rb");
    if(!aea)
    {
        fprintf(stderr, "fopen: %s\n", strerror(errno));
        return -1;
    }

    uint8_t hdr[12];
    if(fread(hdr, sizeof(hdr), 1, aea) != 1)
    {
        fprintf(stderr, "fread(hdr): %s\n", strerror(errno));
        fclose(aea);
        return -1;
    }

    if(LE32(&hdr[0]) != 0x31414541 || LE32(&hdr[4]) != 0x1)
    {
        fprintf(stderr, "Not an AEA1!\n");
        fclose(aea);
        return -1;
    }

    uint32_t sz = LE32(&hdr[8]);
    uint8_t *meta = malloc(sz);
    if(!meta)
    {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        fclose(aea);
        return -1;
    }

    if(fread(meta, sz, 1, aea) != 1)
    {
        fprintf(stderr, "fread(meta): %s\n", strerror(errno));
        fclose(aea);
        return -1;
    }
    fclose(aea);
    aea = NULL;

#ifdef WITH_HPKE
    char *keyURL = NULL;
    char *hpkeData = NULL;
#endif
    bool first = true;
    bool found = false;
    if(act == kActDump)
    {
        printf("{");
    }
    for(size_t off = 0; off < sz; )
    {
        if(sz - off < 4)
        {
            fprintf(stderr, "Too little data left for prop length at offset 0x%zx.\n", off);
            return -1;
        }
        uint32_t len = LE32(meta + off);
        if(len < 4)
        {
            fprintf(stderr, "Prop length says less than 4 bytes at offset 0x%zx - too short for the length itself.\n", off);
            return -1;
        }
        if(len > sz - off)
        {
            fprintf(stderr, "Prop length overflows metadata size at offset 0x%zx.\n", off);
            return -1;
        }
        len -= 4;
        off += 4;
        const char *name = (char*)meta + off;
        uint32_t namelen = strnlen(name, len);
        if(namelen >= len)
        {
            fprintf(stderr, "Prop name unterimnated at offset 0x%zx.\n", off);
            return -1;
        }
        len -= namelen + 1;
        off += namelen + 1;
        const char *value = (char*)meta + off;
        off += len;

        switch(act)
        {
            case kActDump:
                if(first)
                {
                    first = false;
                }
                else
                {
                    printf(",");
                }
                printf("\n    ");
                if(!json_print_string(name, namelen))
                {
                    fprintf(stderr, "Prop name is not safe to print as JSON: %s\n", name);
                    return -1;
                }
                printf(": ");
                if(!json_print_string(value, len))
                {
                    fprintf(stderr, "Prop value is not safe to print as JSON for name: %s\n", name);
                    return -1;
                }
                break;

            case kActList:
                printf("%s\n", name);
                break;

            case kActValue:
                if(strcmp(prop, name) == 0)
                {
                    found = true;
                    fwrite(value, len, 1, stdout);
                    printf("\n");
                }
                break;

#ifdef WITH_HPKE
            case kActUnwrapKey:
            {
                char **ptr = NULL;
                if(strcmp(name, "com.apple.wkms.fcs-key-url") == 0)
                {
                    ptr = &keyURL;
                }
                else if(strcmp(name, "com.apple.wkms.fcs-response") == 0)
                {
                    ptr = &hpkeData;
                }
                if(ptr)
                {
                    if(*ptr)
                    {
                        fprintf(stderr, "Prop found twice: %s\n", name);
                        return -1;
                    }
                    size_t l = strnlen(value, len);
                    if(l != len)
                    {
                        fprintf(stderr, "Prop has NUL bytes: %s\n", name);
                        return -1;
                    }
                    *ptr = strndup(value, len);
                    if(!*ptr)
                    {
                        fprintf(stderr, "malloc: %s\n", strerror(errno));
                        return -1;
                    }
                }
                break;
            }
#endif

            default:
                break;
        }
    }
    if(act == kActDump)
    {
        printf("\n}\n");
    }
    
    free(meta);

    if(act == kActValue && !found)
    {
        return 2;
    }

#ifdef WITH_HPKE
    if(act == kActUnwrapKey)
    {
        if(!hpkeData)
        {
            fprintf(stderr, "Failed to find com.apple.wkms.fcs-response. Is this an OTA?\n");
            return -1;
        }

        char *encRequest = NULL;
        char *wrappedKey = NULL;
        if(!extract_hpke_fields(hpkeData, &encRequest, &wrappedKey))
        {
            return -1;
        }
        free(hpkeData);

        if(strlen(encRequest) % 4 != 0)
        {
            fprintf(stderr, "enc-request is not a multiple of 4 bytes.\n");
            return -1;
        }
        if(strlen(wrappedKey) != WRAPPED_KEY_BASE64_LEN)
        {
            fprintf(stderr, "wrapped-key has wrong length.\n");
            return -1;
        }
        size_t encReqLen = 0;
        if(!b64d(encRequest, &encReqLen))
        {
            fprintf(stderr, "enc-request is not valid base64.\n");
            return -1;
        }
        size_t wrappedKeyLen = 0;
        if(!b64d(wrappedKey, &wrappedKeyLen))
        {
            fprintf(stderr, "wrapped-key is not valid base64.\n");
            return -1;
        }
        if(wrappedKeyLen != WRAPPED_KEY_LEN)
        {
            fprintf(stderr, "Decoded wrapped-key has wrong length.\n");
            return -1;
        }

        char *key = NULL;
        if(keyfile)
        {
            key = read_file(keyfile);
        }
        else
        {
            if(!keyURL)
            {
                fprintf(stderr, "Failed to find com.apple.wkms.fcs-key-url. I guess you need to bring your own key?\n");
                return -1;
            }
            key = fetch(keyURL);
        }
        if(keyURL)
        {
            free(keyURL);
        }
        if(!key)
        {
            return -1;
        }

        if(!hpke_receive(key, encRequest, encReqLen, wrappedKey))
        {
            return -1;
        }

        b64p((void*)wrappedKey, UNWRAPPED_KEY_LEN);
        printf("\n");

        free(key);
        free(encRequest);
        free(wrappedKey);
    }
#endif

    return 0;
}
