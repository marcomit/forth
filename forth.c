#include <ctype.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OBJ_TYPE_STRING 1
#define OBJ_TYPE_INT 2
#define OBJ_TYPE_BOOL 3
#define OBJ_TYPE_SYMBOL 4
#define OBJ_TYPE_LIST 5
#define OBJ_TYPE_TUPLE 6

#define OBJ_LIST_LEN 16
#define OBJ_MAX_INT_LEN 128
#define OBJ_MAX_STRING_LEN 128
#define OBJ_HASHTABLE_LEN 256

#define refcounted(I)                                                          \
  I refcount;                                                                  \
  void (*free)(void *)

#define retain(x) do { if (x) (x)->refcount++; } while(0)                      \

#define release(x)                                                             \
  do {                                                                         \
  if (x)                                                                       \
    if (--(x)->refcount == 0) {                                                \
      if ((x)->free) (x)->free(x);                                             \
      else free(x);                                                            \
    }                                                                          \
  } while (0)

#define resizable(T)                                                           \
    T *ptr;                                                                    \
    size_t len;                                                                \
    size_t size

#define push(l, e) do {                                                        \
  if ((l).len >= (l).size) {                                                   \
    (l).size = (l).size ? (l).size << 1 : OBJ_LIST_LEN;                        \
    (l).ptr = xrealloc((l).ptr, (l).size * sizeof(*(l).ptr));                  \
  }                                                                            \
  (l).ptr[(l).len++] = (e);                                                    \
} while(0)

#define pop(l) ({                                                              \
    __typeof(*(l).ptr) result = {0};                                           \
    if ((l).len > 0) {                                                         \
        result = (l).ptr[--(l).len];                                           \
    }                                                                          \
    result;                                                                    \
})

#define top(l) (l).ptr[(l).len - 1]

/* ==================================== Object structure ===================== */

typedef struct bucket_t {
  char *key;
  void *value;
  struct bucket_t *next;
} bucket_t;

typedef struct map {
  refcounted(int);
  resizable(bucket_t *);
} hmap;

typedef struct obj {
  refcounted(int);
  int type;
  union {
    int i;
    struct {
      resizable(char);
    } s;
    struct {
      resizable(struct obj *);
    } l;
  };
} obj_t;


typedef struct context_t {
  refcounted(int);
  obj_t *stack;
  hmap *symbols; /* hash map to store the functions associated to the symbols */
  hmap *vars; /* variables stored here */
  struct context_t *parent;
} context_t;

typedef struct parser_t {
  char *program;
  char *current;
} parser_t;


typedef struct func_t {
  void *func;
  int arity;
} func_t;


obj_t *compile(char *);
 void exec(obj_t *, context_t *);

/* ================================== Memory allocator wrapper ============================ */
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

/* ======================================= Hash table ===================================== */

#define hmapIndex(m, s) hash(s) & ((m)->size - 1)
#define hmapNode(m, s) (m)->ptr[hmapIndex(m, s)]

hmap *newHmap() {
  hmap *h = xmalloc(sizeof(hmap));
  h->ptr = xmalloc(sizeof(bucket_t *) * OBJ_HASHTABLE_LEN);
  h->size = OBJ_HASHTABLE_LEN;
  h->len = 0;
  return h;
}

void freeBucket(bucket_t *node, int recursive) {
  if (!node) return;
  if (node->next && recursive) freeBucket(node->next, recursive);
  free(node);
}

void freeHmap(hmap *m) {
  for (size_t i = 0; i < m->size; i++) {
    freeBucket(m->ptr[i], 1);
  }
  free(m);
}

uint32_t hash(char *string) {
  uint32_t h = 5381;
  for (char *c = string; *c; c++) {
    h = h * 33 + *c;
  }
  return h;
}

int hmapHas(hmap *m, char *key) {
  bucket_t *node = hmapNode(m, key);
  while (node) {
    if (!strcmp(node->key, key)) return 1;
    node = node->next;
  }
  return 0;
}

void *hmapGet(hmap *m, char *key) {
  bucket_t *node = hmapNode(m, key);
  while (node) {
    if (!strcmp(node->key, key)) return node->value;
    node = node->next;
  }
  return NULL;
}

void hmapSet(hmap *m, char* key, void *value) {
  uint32_t index = hmapIndex(m, key);
  bucket_t *node = xmalloc(sizeof(bucket_t));
  node->key = strdup(key);
  node->value = value;
  bucket_t *dummy = m->ptr[index];
  if (!dummy) {
    m->ptr[index] = node;
    return;
  }
  while (dummy && dummy->next) {
    if (strcmp(dummy->key, key) == 0) {
      return;
    }
  }
  dummy->next = node;
}

/* ==================================== Object management ================================= */

obj_t *newObj(int type) {
  obj_t *o = xmalloc(sizeof(obj_t));
  o->type = type;
  return o;
}

obj_t *newStr(char *c, size_t len) {
  obj_t *str = newObj(OBJ_TYPE_STRING);
  str->s.ptr = c;
  str->s.len = len;
  return str;
}

obj_t *newSym(char *c, size_t len) {
  obj_t *sym = newStr(c, len);
  sym->type = OBJ_TYPE_SYMBOL;
  return sym;
}

obj_t *newInt(int val) {
  obj_t *o = newObj(OBJ_TYPE_INT);
  o->i = val;
  return o;
}

obj_t *newBool(int val) {
  obj_t *o = newInt(val);
  o->type = OBJ_TYPE_BOOL;
  return o;
}

obj_t *newList() {
  obj_t *list = newObj(OBJ_TYPE_LIST);
  list->l.len = 0;
  list->l.size =  OBJ_LIST_LEN;
  list->l.ptr = xmalloc(sizeof(obj_t *) * OBJ_LIST_LEN);
  return list;
}

obj_t *copy(obj_t *original) {
  obj_t *cloned = newObj(original->type);
  switch (original->type) {
    case OBJ_TYPE_BOOL:
    case OBJ_TYPE_INT:
      cloned->i = original->i;
      break;
    case OBJ_TYPE_STRING:
    case OBJ_TYPE_SYMBOL:
      cloned->s.ptr = strdup(original->s.ptr);
      cloned->s.len = original->s.len;
      cloned->s.size = original->s.size;
      break;
    case OBJ_TYPE_LIST:
      cloned->l.ptr = xmalloc(sizeof(obj_t *) * original->l.size);
      cloned->l.len = original->l.len;
      cloned->l.size = original->l.size;
      for (size_t i = 0; i < original->l.len; i++) {
        cloned->l.ptr[i] = copy(original->l.ptr[i]);
      }
  }
  return cloned;
}

void print(obj_t *o) {
  if (!o) {
    printf("null");
    return;
  }
  switch (o->type) {
    case OBJ_TYPE_BOOL:
      printf("bool(%s)", o->i ? "true" : "false");
      break;
    case OBJ_TYPE_INT:
      printf("int(%d)", o->i);
      break;
    case OBJ_TYPE_STRING:
      printf("string(\"%s\")", o->s.ptr);
      break;
    case OBJ_TYPE_SYMBOL:
      printf("symbol(%s)", o->s.ptr);
      break;
    case OBJ_TYPE_LIST:
      printf("list(");
      for (size_t i = 0; i < o->l.len; i++) {
        print(o->l.ptr[i]);
      }
      printf(")");
      break;
    case OBJ_TYPE_TUPLE:
      printf("tuple(");
      for (size_t i = 0; i < o->l.len; i++) {
        print(o->l.ptr[i]);
      }
      printf(")");
      break;
    default:
      printf("undefined");
  }
  printf("\n");
}

context_t *newContext(context_t *parent) {
  context_t *ctx = xmalloc(sizeof(context_t));
  ctx->stack = newList();
  ctx->vars = newHmap();
  ctx->symbols = newHmap();
  ctx->parent = parent;
  return ctx;
}

obj_t *getObj(char *name, context_t *ctx) {
  context_t *curr = ctx;
  while (curr) {
    obj_t *var = hmapGet(curr->vars, name);
    if (var) return var;
    curr = curr->parent;
  }
  return NULL;
}
  
func_t *getFunc(char *name, context_t *ctx) {
  context_t *curr = ctx;
  while (curr) {
    func_t *f = (func_t *)hmapGet(curr->symbols, name);
    if (f) return f;
    curr = curr->parent;
  }
    
  return NULL;
}

/* ======================================= Turn program into list ==============================*/

#define consume(parser) *(++(parser)->current)
#define peek(parser) *(parser)->current

void parseSpaces(parser_t *parser) {
  while (peek(parser) && isspace(*parser->current)) consume(parser);
}

obj_t *parseInt(parser_t *parser) {
  char *start = parser->current;
  if (peek(parser) == '-') {
    consume(parser);
    if (!isdigit(peek(parser))) return newSym(strdup("-"), 1);
  }
  while (peek(parser) && isdigit(*parser->current)) consume(parser);
  size_t len = parser->current - start;
  if (len == 0 || len > 128) return NULL;
  char buff[128];
  memcpy(buff, start, len + 1);
  return newInt(atoi(buff));
}

obj_t *parseSymbol(parser_t *parser) {
  char *start = parser->current;
  while (peek(parser) && !isspace(*parser->current)) consume(parser);
  size_t len = parser->current - start;
  char *buff = xmalloc(len + 1);
  memcpy(buff, start, len);
  buff[len] = 0;
  return newSym(buff, len);
}

char *takeListInside(parser_t *parser, char begin, char end) {
  if (*parser->current != begin) return NULL;
  consume(parser);
  char *start = parser->current;
  while (peek(parser) && *parser->current != end) consume(parser);
  size_t len = parser->current - start;
  if (peek(parser) == end) consume(parser);
  char *buff = xmalloc(len + 1);
  memcpy(buff, start, len);
  buff[len] = 0;
  return buff;
}

obj_t *parseString(parser_t *parser) {
  char *str = takeListInside(parser, '"', '"');
  if (!str) return NULL;
  return newStr(str, strlen(str));
}

obj_t *parseList(parser_t *parser) {
  if (*parser->current != '[') return NULL;
  consume(parser);
  char *start = parser->current;
  int level = 1;
  while (peek(parser) && level > 0) {
    if (peek(parser) == '[') level++;
    else if (peek(parser) == ']') level--;
    consume(parser);
  }
  size_t len = parser->current - start - 1;
  char buff[len+1];
  memcpy(buff, start, len);
  buff[len] = 0;
  obj_t *list = compile(buff);

  return list;
}

obj_t *compile(char *text) {
  parser_t parser;
  parser.program = text;
  parser.current = text;
  obj_t *parsed = newList();

  while (*parser.current) {
    obj_t *o = NULL;
    char *start = parser.current;
    parseSpaces(&parser);
    if (!peek(&parser)) break;

    if (peek(&parser) == '"') {
      o = parseString(&parser);
    } else if (peek(&parser) == '[') {
      o = parseList(&parser);
    } else if (peek(&parser) == '-' || isdigit(peek(&parser))) {
      o = parseInt(&parser);
    } else {
      o = parseSymbol(&parser);
    }
    if (o) push(parsed->l, o);
    else printf("Error parsing near %s ...\n", start);
  }

  return parsed;
}

/* ================================ Executing the object ================================ */
#define binary_params(ctx) obj_t *second = pop((ctx)->stack->l); obj_t *first = pop((ctx)->stack->l)
#define unary_params(ctx) obj_t *last = pop((ctx)->stack->l)

/* ======================== Arithmetic operations ======================== */
obj_t *plus(context_t *ctx) { binary_params(ctx); return newInt(first->i + second->i);}
obj_t *minus(context_t *ctx) { binary_params(ctx); return newInt(first->i - second->i); }
obj_t *division(context_t *ctx) { binary_params(ctx); return newInt(first->i / second->i); }
obj_t *mul(context_t *ctx) { binary_params(ctx); return newInt(first->i * second->i); }
obj_t *printObj(context_t *ctx) { unary_params(ctx); print(last); return NULL; }

/* ========================== Stack operations =========================== */
obj_t *dup(context_t *ctx) { return copy(top(ctx->stack->l)); }
obj_t *drop(context_t *ctx) { pop(ctx->stack->l); return NULL; }
obj_t *swap(context_t *ctx) { binary_params(ctx); push(ctx->stack->l, second); push(ctx->stack->l, first); return NULL; }

/* ============================ Control flows ============================ */
obj_t *consumeIf(context_t *ctx) {
  obj_t *branch = pop(ctx->stack->l);
  obj_t *condition = pop(ctx->stack->l);
  if (condition->i) {
    exec(branch, ctx);
  }
  return NULL;
}

obj_t *consumeIfElse(context_t *ctx) {
  obj_t *fbranch = pop(ctx->stack->l);
  obj_t *tbranch = pop(ctx->stack->l);
  obj_t *condition = pop(ctx->stack->l);
  exec(condition->i ? tbranch : fbranch, ctx);
  return NULL;
}

void consumeObject(context_t *ctx, obj_t *o) {
  if (o->type != OBJ_TYPE_SYMBOL) {
    push(ctx->stack->l, o);
    return;
  }
  func_t *sym = (func_t *)hmapGet(ctx->symbols, o->s.ptr);
  if (!sym) {
    fprintf(stderr, "Error: Symbol '%s' not found!\n", o->s.ptr);
    exit(1);
  }
  if (ctx->stack->l.len < (size_t)sym->arity) {
    fprintf(stderr, "Expected at least %d elements, got %zu for symbol %s\n", sym->arity, ctx->stack->l.len, o->s.ptr);
    exit(1);
  }
  obj_t *(*func)(context_t *) = sym->func;
  obj_t *result = func(ctx);
  if (result) {
    printf("result pushed to the stack ");
    print(result);
    push(ctx->stack->l, result);
  }
}

void loadSymbols(context_t *ctx) {
  /* === Arithmetic symbols === */
  hmapSet(ctx->symbols, "+", &(func_t){plus, 2});
  hmapSet(ctx->symbols, "-", &(func_t){minus, 2});
  hmapSet(ctx->symbols, "/", &(func_t){division, 2});
  hmapSet(ctx->symbols, "*", &(func_t){mul, 2});
  hmapSet(ctx->symbols, ".", &(func_t){printObj, 1});

  /* ==== Stack operations ==== */
  hmapSet(ctx->symbols, "dup", &(func_t){dup, 1});
  hmapSet(ctx->symbols, "drop", &(func_t){drop, 1});
  hmapSet(ctx->symbols, "swap", &(func_t){swap, 2});
  
  /* ====== Control flow ====== */
  hmapSet(ctx->symbols, "if", &(func_t){consumeIf, 2});
  hmapSet(ctx->symbols, "ifelse", &(func_t){consumeIfElse, 2});
}

void exec(obj_t *list, context_t *parent) {
  context_t *ctx = newContext(parent);
  if (!parent) loadSymbols(ctx);
  
  for (size_t i = 0; i < list->l.len; i++) {
    consumeObject(ctx, list->l.ptr[i]);
  }

}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage %s <filename>\n", *argv);
    return 1;
  }

  FILE *fd = fopen(argv[1], "r");
  fseek(fd, 0, SEEK_END);
  long flen = ftell(fd);
  char *prgtext = xmalloc(flen + 1);
  fseek(fd, 0, SEEK_SET);
  fread(prgtext, flen, 1, fd);
  prgtext[flen] = 0;
  fclose(fd);

  obj_t *parsed = compile(prgtext);
  exec(parsed, NULL);
}
