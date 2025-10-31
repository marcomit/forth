#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define OBJ_TYPE_STRING 1
#define OBJ_TYPE_INT 2
#define OBJ_TYPE_BOOL 3
#define OBJ_TYPE_SYMBOL 4
#define OBJ_TYPE_LIST 5

#define retain(x)                                                              \
  if (x)                                                                       \
  (x)->refcount++

#define release(x)                                                             \
  if (x)                                                                       \
    if (--(x)->refcount == 0)                                                  \
      if ((x)->free)                                                           \
        (x)->free(x);                                                          \
      else                                                                     \
        free(x)

#define append(array, element)                                                 \
  do {                                                                         \
    if ((array)->l.len >= (array)->l.size) {                                   \
      (array)->l.size <<= 1;                                                   \
      (array)->l.ptr = xrealloc((array)->l.ptr, (array)->l.size);              \
    }                                                                          \
    (array)->l.ptr[(array)->l.len++] = element;                                \
  } while (0)

/* Structure of the object defined */
typedef struct obj {
  int refcount;
  int type;
  union {
    int i;
    struct {
      char *ptr;
      size_t len;
      size_t size;
    } s;
    struct {
      struct obj **ptr;
      size_t len;
      size_t size;
    } l;
  };
} obj;

typedef struct context {
  obj *stack;
  obj *bstack;
  int bdepth;
  obj *vars;
} context;

/* Memory allocator wrapper */
void *xmalloc(size_t bytes) {
  void *ptr = malloc(bytes);
  if (!ptr) {
    fprintf(stderr, "Unable to allocate %zu\n", bytes);
    exit(1);
  }
  return ptr;
}
void *xrealloc(void *ptr, size_t bytes) {
  void *new = realloc(ptr, bytes);
  if (!new) {
    fprintf(stderr, "Unable to reallocate %zu\n", bytes);
    exit(1);
  }
  return new;
}

obj *newObj(int type) {
  obj *o = xmalloc(sizeof(obj));
  o->type = type;
  return o;
}

obj *newStr(char *c, size_t len) {
  obj *str = newObj(OBJ_TYPE_STRING);
  str->s.ptr = c;
  str->s.len = len;
  return str;
}

obj *newSym(char *c, size_t len) {
  obj *sym = newStr(c, len);
  sym->type = OBJ_TYPE_SYMBOL;
  return sym;
}

obj *newInt(int val) {
  obj *o = newObj(OBJ_TYPE_INT);
  o->i = val;
  return o;
}

obj *newBool(int val) {
  obj *o = newInt(val);
  o->type = OBJ_TYPE_BOOL;
  return o;
}

obj *newList() {
  obj *list = newObj(OBJ_TYPE_LIST);
  return list;
}

context *newCtx() {
  context *ctx = xmalloc(sizeof(context));
  ctx->stack = newList();
  ctx->bstack = newList();
  ctx->vars = newList();
  return ctx;
}

int tokenizeNumber(char **curr, size_t *len) {
  char *start = *curr;
  while (*curr && isdigit(**curr)) {
    (*curr)++;
  }
  *len = *curr - start;
  return len > 0;
}

int tokenizeSym(char **curr, size_t *len) {
  char *start = *curr;
  while (*curr && isalnum(**curr))
    (*curr)++;
  *len = *curr - start;
  return 1;
}

int tokenizeStr(char **curr, size_t *len) {
  char *start = *curr;
  if (**curr != '"')
    return 0;

  (*curr)++;

  while (*curr && **curr != '"')
    (*curr)++;
  *len = *curr - start;
  return **curr != 0;
}

void tokenize(context *ctx, char **curr) {
  int (*tok[])(char **, size_t *) = {tokenizeNumber, tokenizeStr, tokenizeSym};
  while (*curr) {
    if (!isalnum(**curr))
      continue;
    char *start = *curr;
    size_t len = 0;
  }
}

void readFile(context *ctx, char *filename) {
  FILE *fd = fopen(filename, "r");
  if (!fd) {
    perror("Unable to open file:");
    exit(1);
  }
  char buff[1024];
  while (fgets(buff, sizeof(buff), fd)) {
  }
  fclose(fd);
}

int main(int argc, char **argv) {
  if (argc != 1) {
    printf("Usage: %s <filename>\n", argv[0]);
    return 1;
  }

  context *ctx = newCtx();
}
