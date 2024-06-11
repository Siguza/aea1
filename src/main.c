#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define LE32(ptr) ((uint32_t)((ptr)[3]) << 24 | (uint32_t)((ptr)[2]) << 16 | (uint32_t)((ptr)[1]) << 8 | (uint32_t)((ptr)[0]))

typedef enum
{
    kActDump,
    kActList,
    kActValue,
    kActUnwrapKey,
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

int main(int argc, const char **argv)
{
    action_t act = kActDump;
    int aoff = 1;
    if(argv[aoff][0] == '-')
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
                act = kActUnwrapKey;
                break;

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
                        "    %s file.aea        - Dump all props as JSON\n"
                        "    %s file.aea [prop] - Dump single prop value raw\n"
                        "    %s -l file.aea     - Dump prop names, one per line\n"
                        , argv[0], argv[0], argv[0]);
        return 1;
    }

    const char *infile = argv[aoff];
    const char *prop = NULL;
    if(argc - aoff > 1)
    {
        switch(act)
        {
            case kActDump:
                act = kActValue;
                prop = argv[aoff + 1];
                break;

            case kActUnwrapKey:
                fprintf(stderr, "TODO\n");
                __builtin_trap();

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

    return 0;
}
