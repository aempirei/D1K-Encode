
/*
 * D1K - encodes or decodes one or more files in the 
 * D1K_ENCODE format using ascii dicks.  a single
 * .d1k file can contain multiple encoded files.
 *
 * this code has finally been released to the public
 * after many years of lying dormant and dusty for
 * a previously unreleased project.
 *
 * (c) 2006 by van Hauser / THC <vh@thc.org> www.thc.org
 * The GPL 2.0 applies to this code.
 *
 * For usage hints, type "d1k"
 *
 * a typical decode:
 *
 * d1k d gadi.d1k
 *
 * a typical encode:
 *
 * d1k e my_name_is_gadi_evron.mp3 el8.4.txt > woohoo.d1k
 *
 * To compile: gcc -o d1k d1k.c
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#define DIKS     16
#define COLUMNS  80
#define DIKMAGIC 0x1DEADFED

int longestdik;

typedef struct {
  const char *string;
  unsigned int value;
  unsigned int length;
} DIK;

/*
 * each of the 15 dicks used to encode data here have been
 * modeled after the penises of famous infosec experts
 * taken from my extensive private collection of various
 * voyuer photos ive secretly taken over the years at
 * security conferences. as you can see, "8=D" models FX's
 * penis perfectly. the jizz uses the ANSI-X3.4-1986(R1997)
 * sperm symbol "~".
 *
 */

DIK dik[DIKS] = {
  {"~", 0}, {"8===D", 0}, {"8==D", 0}, {"8=D", 0},
  {"8==o", 0}, {"8=o", 0}, {"c===3", 0}, {"c==3", 0},
  {"c=3", 0}, {"c===8", 0}, {"c==8", 0}, {"c=8", 0},
  {"o==3", 0}, {"o=3", 0}, {"o==8", 0}, {"o=8", 0}
};

void dik_init();
int dik_compare(const void *, const void *);

int diktoi(const char *);
const DIK *itodik(unsigned int);

void dik_encode(const char *);
int dik_encode_int(int, FILE *);
int dik_encode_string(const char *, FILE *);

void dik_decode(const char *);
int dik_decode_int(int *, FILE *);
char * dik_decode_string(FILE *);
int dik_decode_file(FILE *);

int dikputc(int, FILE *);
int dikgetc(FILE *);

void usage(const char *);

int main(int argc, char **argv) {

  dik_init();

  int i;
  int mode;

  if (argc < 3) {
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  if (strcmp(argv[1], "e") == 0) {
    mode = 'e';
  } else if (strcmp(argv[1], "d") == 0) {
    mode = 'd';
  } else {
    mode = -1;
  }

  i = 2;

  while (i < argc) {
    switch (mode) {
    case 'e':
      dik_encode(argv[i]);
      break;
    case 'd':
      dik_decode(argv[i]);
      break;
    }

    i++;
  }

  exit(EXIT_SUCCESS);
}

void usage(const char *arg) {

  putchar('\n');
  printf("usage: %s [ed] filename1 [filename2 ... filenameN]\n", arg);
  putchar('\n');
}

int dik_encode_int(int length, FILE * stream) {

  uint32_t netlen;
  unsigned char byte[sizeof(uint32_t)];
  int i;

  netlen = htonl(length);

  memcpy(byte, &netlen, sizeof(uint32_t));

  i = 0;
  while (i < sizeof(uint32_t)) {
    if (dikputc(byte[i], stream) == EOF) {
      return EOF;
    }
    i++;
  }

  return 0;
}

int dik_encode_string(const char *string, FILE * stream) {
	
  int length;
  int i;

  length = strlen(string);

  if (dik_encode_int(length, stream) == EOF) {
    return EOF;
  }

  i = 0;
  while (i < length) {
    if (dikputc(string[i], stream) == EOF) {
      return EOF;
    }
    i++;
  }

  return 0;
}

void dik_encode(const char *filename) {

  struct stat statinfo;
  FILE *f;
  int length;
  int c;
  char *base;
  char *ptr;

  fprintf(stderr, "encoding %s\n", filename);

  f = fopen(filename, "r");
  if (f == NULL) {
    fprintf(stderr, "failed to open %s: %s\n", filename, strerror(errno));
    exit(EXIT_FAILURE);
  }

  fseek(f, 0, SEEK_END);
  length = ftell(f);
  rewind(f);

  if (stat(filename, &statinfo) == -1) {
    fprintf(stderr, "stat failed on %s: %s\n", filename, strerror(errno));
    exit(EXIT_FAILURE);
  }

  ptr = strdup(filename);
  base = basename(ptr);

  dik_encode_int(DIKMAGIC, stdout);
  dik_encode_string(base, stdout);
  dik_encode_int(statinfo.st_mode & 0777, stdout);
  dik_encode_int(length, stdout);

  free(ptr);

  while ((c = fgetc(f)) != EOF) {
    dikputc(c, stdout);
  }

  fclose(f);
}

char * dik_decode_string(FILE * stream) {

  int length;
  char *string;
  int i;
  int c;

  if (dik_decode_int(&length, stream) == EOF) {
    return NULL;
  }

  string = malloc(length + 1);

  i = 0;
  while (i < length) {
    c = dikgetc(stream);
    if (c == EOF) {
      free(string);
      return NULL;
    }
    string[i] = c;
    i++;
  }

  string[i] = '\0';

  return (string);
}

int dik_decode_file(FILE * stream) {

  struct stat statinfo;
  FILE *f;
  char *filename;
  int magic;
  int length;
  int i;
  int c;
  int answer;
  char line[80];
  int perms;

  if (dik_decode_int(&magic, stream) == EOF) {
    return EOF;
  }

  if (magic != DIKMAGIC) {
    fputs("invalid magic number\n", stderr);
    exit(EXIT_FAILURE);
  }

  filename = dik_decode_string(stream);

  if (filename == NULL) {
    fputs("no filename found\n", stderr);
    exit(EXIT_FAILURE);
  }

  if (dik_decode_int(&perms, stream) == EOF) {
    fputs("cannot read file permissions\n", stderr);
    exit(EXIT_FAILURE);
  }

  printf("extracting %s\n", filename);

  if (dik_decode_int(&length, stream) == EOF) {
    fprintf(stderr, "couldn't determine length of %s\n", filename);
    exit(EXIT_FAILURE);
  }

  answer = 'Y';

  if (stat(filename, &statinfo) == 0) {
    do {
      printf("%s already exists, overwrite? (Y/N) ", filename);
      fgets(line, sizeof(line) - 1, stdin);
      answer = toupper(line[0]);
    }
    while (answer != 'Y' && answer != 'N');

  }

  if (answer == 'Y') {
    f = fopen(filename, "w");
    if (f == NULL) {
      fprintf(stderr, "failed to open %s: %s\n", filename, strerror(errno));
      exit(EXIT_FAILURE);
    }
  } else if (answer == 'N') {
    f = NULL;
    printf("skipping %s\n", filename);
  }

  i = 0;
  while (i < length) {
    c = dikgetc(stream);

    if (c == EOF) {
      perror("unexpected read error");
      exit(EXIT_FAILURE);
    }

    if (answer == 'Y') {
      if (fputc(c, f) == EOF) {
        perror("unexpected write error");
        exit(EXIT_FAILURE);
      }
    }

    i++;
  }

  if (answer == 'Y') {
    fclose(f);
    chmod(filename, perms);
  }

  free(filename);

  return 0;
}

void dik_decode(const char *filename) {

  FILE *f;

  printf("decoding %s\n", filename);

  f = fopen(filename, "r");

  while (dik_decode_file(f) != EOF) {
  }

  fclose(f);
}

int dik_compare(const void *a, const void *b) {

  const DIK *dik1 = (const DIK *)a;
  const DIK *dik2 = (const DIK *)b;
  return strcmp(dik2->string, dik1->string);
}

void dik_init() {

  unsigned int i;
  qsort(dik, DIKS, sizeof(DIK), dik_compare);

  longestdik = 0;
  i = 0;
  while (i < DIKS) {
    dik[i].value = i;
    dik[i].length = strlen(dik[i].string);
    if (longestdik < dik[i].length) {
      longestdik = dik[i].length;
    }
    i++;
  }
}

unsigned int column = 0;

int dikgetnibble(FILE * stream) {

  char *somedik;
  char buf[2];

  int length;
  int value;
  int c;

  somedik = malloc(longestdik + 1);

  somedik[0] = '\0';
  memset(buf, 0, sizeof(buf));

  length = 0;

  do {
    c = fgetc(stream);

    if (isspace(c)) {
      continue;
    }

    if (c == EOF) {
      return -1;
    }

    buf[0] = c;

    strcat(somedik, buf);

    value = diktoi(somedik);

    if (value != -1) {
      free(somedik);
      return value;
    }

  }
  while (length < longestdik);

  free(somedik);
  return -1;
}

int dikgetc(FILE * stream) {

  int hi, lo;
  unsigned char c;

  hi = dikgetnibble(stream);
  if (hi == -1) {
    return EOF;
  }

  lo = dikgetnibble(stream);
  if (lo == -1) {
    return EOF;
  }

  c = (hi << 4) | lo;

  return c;
}

int dik_decode_int(int *ptr, FILE * stream) {

  unsigned char byte[sizeof(uint32_t)];
  uint32_t netlen;

  int i;
  int c;

  i = 0;

  while (i < sizeof(uint32_t)) {
    c = dikgetc(stream);
    if (c == EOF) {
      return EOF;
    }

    byte[i] = c;

    i++;
  }

  memcpy(&netlen, byte, sizeof(uint32_t));

  *ptr = ntohl(netlen);

  return 0;
}

int dikputc(int c, FILE * stream) {

  unsigned char ch;
  const DIK *dptr;

  ch = (unsigned char)c;

  dptr = itodik((ch >> 4) & 15);

  column += dptr->length;

  if (column > COLUMNS) {
    fputc('\n', stream);
    column = dptr->length;
  }

  if (fputs(dptr->string, stream) == EOF) {
    return EOF;
  }

  dptr = itodik(ch & 15);

  column += dptr->length;

  if (column > COLUMNS) {
    fputc('\n', stream);
    column = dptr->length;
  }

  if (fputs(dptr->string, stream) == EOF) {
    return EOF;
  }

  return 0;
}

const DIK * itodik(unsigned int i) {

  if (i >= DIKS) {
    return NULL;
  }

  return &dik[i];
}

int diktoi(const char *string) {

  DIK key;
  DIK *found;

  if (string == NULL) {
    return -1;
  }

  key.string = string;

  found = bsearch(&key, dik, DIKS, sizeof(DIK), dik_compare);

  if (found == NULL) {
    return (-1);
  }

  return found->value;
}

