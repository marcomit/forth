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

/* Error messages */
#define VAR_NOT_FOUND(ptr) do {                                                 \
  fprintf(stderr, "Variable %s not found\n", ptr);                              \
  exit(1);                                                                      \
} while(0)

#define EXPECTED_TYPE(o, t) do {                                                \
  if ((o)->type == (t)) break;                                                  \
  fprintf(stderr, "Expected type %d, got %d\n", t, (o)->type);                  \
  exit(1);                                                                      \
} while(0)

#define EXPECTED_STACK_LEN(s, n)  do {                                          \
  if ((s).len >= (size_t)(n)) break;                                            \
  fprintf(stderr, "Expected %d arguments, got %zu for ", n, (s).len);           \
  print(o, 0);                                                                  \
  exit(1);                                                                      \
} while(0)

#define refcounted(I)                                                           \
  I refcount;                                                                   \
  void (*free)(void *)

#define initrefcount(o, func) do { (o)->refcount = 1; (o)->free = func;         \
  } while(0)

#define retain(x) do { if (x) (x)->refcount++; } while(0)                       \


#define release(x)                                                              \
  do {                                                                          \
  if (x)                                                                        \
    if (--(x)->refcount == 0) {                                                 \
      if ((x)->free) (x)->free(x);                                              \
      else free(x);                                                             \
      (x) = NULL;                                                               \
    }                                                                           \
  } while (0)

#define resizable(T)                                                            \
    T *ptr;                                                                     \
    size_t len;                                                                 \
    size_t size

#define push(l, e) do {                                                         \
  if ((l).len >= (l).size) {                                                    \
    (l).size = (l).size ? (l).size << 1 : OBJ_LIST_LEN;                         \
    (l).ptr = realloc((l).ptr, (l).size * sizeof(*(l).ptr));                    \
  }                                                                             \
  (l).ptr[(l).len++] = (e);                                                     \
} while(0)

#define pop(l) ({                                                               \
    __typeof(*(l).ptr) result = {0};                                            \
    if ((l).len > 0) {                                                          \
        result = (l).ptr[--(l).len];                                            \
    }                                                                           \
    result;                                                                     \
})

#define top(l) (l).ptr[(l).len - 1]

#define iter(l, n) for(size_t i = 0; i < (l).len; i++) {\
  __typeof(*(l).ptr) n = l.ptr[i];\

#define enditer }

/* ==================================== Object structure ===================== */

typedef struct bucket_t {
  char *key;
  void *value;
  struct bucket_t *next;
} bucket_t;

typedef struct hmap {
  refcounted(int);
  resizable(bucket_t *);
} hmap;

typedef struct obj_t {
  refcounted(int);
  int type;
  union {
    int i; // Used for both integer and boolean values
    struct {
      resizable(char);
    } s; // Used for both string and symbol values
    struct {
      resizable(struct obj_t *);
    } l; // Used for lists
  };
} obj_t;

typedef struct scope_t {
  hmap *symbols; /* hash map to store the functions associated to the symbols. */
  hmap *vars; /* variables stored here. */
  struct scope_t *parent; /* scopes to handle closures.*/
} scope_t;

typedef struct context_t {
  obj_t *stack;
  scope_t *global;
  scope_t *current;
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
 void exec(context_t *, obj_t *);

/* ================================== Memory allocator wrapper ============================ */

void *xmalloc(size_t bytes) {
  void *ptr = malloc(bytes);
  if (ptr) return ptr;
  fprintf(stderr, "Unable to allocate %zu\n", bytes);
  exit(1);
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

void freeObj(void *ptr) {
  obj_t *self = ptr;
  if (self->type == OBJ_TYPE_LIST || self->type == OBJ_TYPE_TUPLE) {
    iter(self->l, curr) release(curr); enditer
  } else if (self->type == OBJ_TYPE_STRING || self->type == OBJ_TYPE_SYMBOL) {
    free(self->s.ptr);
  }
  free(self);
}

obj_t *newObj(int type) {
  obj_t *o = xmalloc(sizeof(obj_t));
  initrefcount(o, freeObj);
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

void print(obj_t *o, int depth) {
  if (!o) {
    printf("null");
    return;
  }
  for (int i = 0; i < depth; i++) printf("  ");
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
      printf("list(\n");
      iter(o->l, curr) print(curr, depth + 1); enditer
      printf(")");
      break;
    case OBJ_TYPE_TUPLE:
      printf("tuple(\n");
      iter(o->l, curr) print(curr, depth + 1); enditer
      printf(")");
      break;
    default:
      printf("undefined");
  }
  printf("\n");
}

void freeScope(struct scope_t *scope) {
  // freeHmap(scope->symbols);
  // freeHmap(scope->vars);
  // free(scope);
}

scope_t *newScope(scope_t *parent) {
  scope_t *scope = xmalloc(sizeof(scope_t));
  scope->parent = parent;
  scope->symbols = newHmap();
  scope->vars = newHmap();
  return scope;
}

func_t *getFunc(context_t *ctx, char *name) {
  scope_t *dummy = ctx->current;
  while (dummy) {
    func_t *val = (func_t *)hmapGet(dummy->symbols, name);
    if (val) return val;
    dummy = dummy->parent;
  }
  return NULL;
}

obj_t *getVar(context_t *ctx, char *name) {
  scope_t *dummy = ctx->current;
  while (dummy) {
    void *val = hmapGet(dummy->vars, name);
    if (val) return (obj_t *)val;
    dummy = dummy->parent;
  }
  return NULL;
}

context_t *newContext() {
  context_t *ctx = xmalloc(sizeof(context_t));
  ctx->stack = newList();
  ctx->global = newScope(NULL);
  ctx->current = ctx->global;
  return ctx;
}


/* ======================================= Turn program into list ==============================*/

#define consume(parser) *(++(parser)->current)
#define peek(parser) *(parser)->current

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
    while (peek(&parser) && isspace(*parser.current)) consume(&parser);
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

#define BINARY_OP(name, op, type)                                         \
obj_t *name(context_t *ctx) {                                             \
    binary_params(ctx);                                                   \
    return type(first->i op second->i);                                   \
}

obj_t *printObj(context_t *ctx) { print(pop(ctx->stack->l), 0); return NULL; }

/* ======================== Arithmetic operations ======================== */
BINARY_OP(plus, +, newInt)
BINARY_OP(minus, -, newInt)
BINARY_OP(division, /, newInt)
BINARY_OP(mul, *, newInt)

/* ========================== Binary operations ========================== */
BINARY_OP(consumeAnd, &&, newBool)
BINARY_OP(consumeOr, ||, newBool)
BINARY_OP(consumeGE, >, newBool)
BINARY_OP(consumeLE, <, newBool)
BINARY_OP(consumeGTE, >=, newBool)
BINARY_OP(consumeLTE, <=, newBool)
BINARY_OP(consumeEQ, ==, newBool)

obj_t *consumeNot(context_t *ctx) { unary_params(ctx); return newBool(!last->i); }

/* ========================== Stack operations =========================== */
obj_t *dup(context_t *ctx) { return copy(top(ctx->stack->l)); }
obj_t *drop(context_t *ctx) { pop(ctx->stack->l); return NULL; }
obj_t *swap(context_t *ctx) { binary_params(ctx); push(ctx->stack->l, second); push(ctx->stack->l, first); return NULL; }

/* ============================ Control flows ============================ */
obj_t *consumeIf(context_t *ctx) {
  obj_t *branch = pop(ctx->stack->l);
  obj_t *condition = pop(ctx->stack->l);
  if (condition->i) {
    exec(ctx, branch);
  }
  return NULL;
}

obj_t *consumeIfElse(context_t *ctx) {
  obj_t *fbranch = pop(ctx->stack->l);
  obj_t *tbranch = pop(ctx->stack->l);
  obj_t *condition = pop(ctx->stack->l);
  exec(ctx, condition->i ? tbranch : fbranch);
  return NULL;
}

obj_t *consumeLoop(context_t *ctx) {
  obj_t *branch = pop(ctx->stack->l);
  obj_t *condition = pop(ctx->stack->l);

  do {
    exec(ctx, condition);
    obj_t *result = top(ctx->stack->l);
    if (result->i) break;
    exec(ctx, branch);
  } while(1);
  return NULL;
}

func_t *newfunc(void *func, int arity) {
  func_t *f = xmalloc(sizeof(func_t));
  f->arity = arity;
  f->func = func;
  return f;
}

void loadSymbols(context_t *ctx) {
  /* === Arithmetic symbols === */
  hmapSet(ctx->current->symbols, "+", newfunc(plus, 2));
  hmapSet(ctx->current->symbols, "-", newfunc(minus, 2));
  hmapSet(ctx->current->symbols, "/", newfunc(division, 2));
  hmapSet(ctx->current->symbols, "*", newfunc(mul, 2));
  hmapSet(ctx->current->symbols, ".", newfunc(printObj, 1));

  /* === Boolean operations === */
  hmapSet(ctx->current->symbols, "and", newfunc(consumeAnd, 2));
  hmapSet(ctx->current->symbols, "or", newfunc(consumeOr, 2));
  hmapSet(ctx->current->symbols, "not", newfunc(consumeNot, 1));

  /* === Integer comparator === */
  hmapSet(ctx->current->symbols, ">", newfunc(consumeGE, 2));
  hmapSet(ctx->current->symbols, "<", newfunc(consumeLE, 2));
  hmapSet(ctx->current->symbols, "==", newfunc(consumeEQ, 2));
  hmapSet(ctx->current->symbols, "<=", newfunc(consumeLTE, 2));
  hmapSet(ctx->current->symbols, ">=", newfunc(consumeGTE, 2));

  /* ==== Stack operations ==== */
  hmapSet(ctx->current->symbols, "dup", newfunc(dup, 1));
  hmapSet(ctx->current->symbols, "drop", newfunc(drop, 1));
  hmapSet(ctx->current->symbols, "swap", newfunc(swap, 2));

  /* ====== Control flow ====== */
  hmapSet(ctx->current->symbols, "if", newfunc(consumeIf, 2));
  hmapSet(ctx->current->symbols, "ifelse", newfunc(consumeIfElse, 2));
  hmapSet(ctx->current->symbols, "loop", newfunc(consumeLoop, 2));
}

int consumeVariables(context_t *ctx, obj_t *o) {
  if (o->s.len == 0) return 0;
  obj_t *val = getVar(ctx, o->s.ptr + 1);
  if (*o->s.ptr == ':') {
    obj_t *last = pop(ctx->stack->l);
    hmapSet(ctx->current->vars, o->s.ptr + 1, last);
  }
  else if (*o->s.ptr == '@') {
    if (!val) VAR_NOT_FOUND(o->s.ptr + 1);
    push(ctx->stack->l, val);
  }
  else if (*o->s.ptr == '!') {
    if (!val) VAR_NOT_FOUND(o->s.ptr + 1);
    EXPECTED_TYPE(val, OBJ_TYPE_LIST);
    exec(ctx, val); 
  }
  else return 0;
  return 1;
}

int consumeSymbol(context_t *ctx, obj_t *o) {
  func_t *sym = getFunc(ctx, o->s.ptr);
  if (!sym) return 0;
  EXPECTED_STACK_LEN(ctx->stack->l, sym->arity);
  obj_t *(*func)(context_t *) = sym->func;
  obj_t *result = func(ctx);
  if (result) push(ctx->stack->l, result);
  return 1;
}

void exec(context_t *ctx, obj_t *list) {
  ctx->current = newScope(ctx->current);
  iter(list->l, o)
    if (o->type != OBJ_TYPE_SYMBOL) {
      push(ctx->stack->l, o);
      continue;
    }
    if (consumeVariables(ctx, o)) continue;
    consumeSymbol(ctx, o);
    
  enditer
  freeScope(ctx->current);
  ctx->current = ctx->current->parent;
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
  context_t *ctx = newContext();
  loadSymbols(ctx);
  exec(ctx, parsed);
}
