
#include <stdio.h>
#include <time.h>

int unsigned_char_to_hex(unsigned char *out, const unsigned char *in, size_t inlen);

int hex_to_unsigned_char(unsigned char *out, const unsigned char *in, size_t inlen);

void print_hex(const char *desp, const unsigned char *s, size_t slen);

void random_string(unsigned char *s, size_t len);

size_t random_number(void);

static const unsigned char ascii_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

static const unsigned char inv_ascii_table[128] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
       0,    1,    2,    3,    4,    5,    6,    7,
       8,    9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,   10,   11,   12,   13,   14,   15, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,   10,   11,   12,   13,   14,   15, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

int unsigned_char_to_hex(unsigned char *out, const unsigned char *in, size_t inlen)
{
    size_t i;

    if (out == NULL)
        return -1;

    for (i = 0; i < inlen; i++) {
        out[0] = ascii_table[in[i] >> 4];
        out[1] = ascii_table[in[i] & 0xf];
        out += 2;
    }

    return 0;
}

int hex_to_unsigned_char(unsigned char *out, const unsigned char *in, size_t inlen)
{
    size_t i;

    if (out == NULL)
        return -1;

    i = 0;
    if (inlen % 2 == 1) {
        out[0] = inv_ascii_table[in[i]];
        if (out[0] == 0xff)
            return -1;
        out++;
        i++;
    }

    for (; i < inlen; i += 2) {
        out[0] = (inv_ascii_table[in[i]] << 4) | inv_ascii_table[in[i+1]];
        // if (out[0] == 0xff)
        //     return FP256_ERR;
        out++;
    }
    return 0;
}

void print_hex(const char *desp, const unsigned char *s, size_t slen)
{
    size_t i;

    for(i = 0; i < strlen(desp); i++)
        printf("%c", desp[i]);

    unsigned char *hex = (unsigned char*)malloc(2*slen);
    unsigned_char_to_hex(hex, s, slen);
    for(i = 0; i < 2*slen; i++)
        printf("%c", hex[i]);
    printf("\n");
    free(hex);
}

/* bad rng, but good for test */
void random_string(unsigned char *s, size_t len)
{
    static int en = 0;
    size_t i;

    srand((unsigned)time(NULL) + en);
    for (i = 0; i < len; i++)
        s[len] = rand() % 256;
    en++;
}

size_t random_number(void)
{
    static int en = 0;
    srand((unsigned)time(NULL) + en);
    en++;
    return (size_t)rand();
}
