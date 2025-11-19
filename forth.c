#include <ctype.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define OBJ_TYPE_STRING 1
#define OBJ_TYPE_INT 2
#define OBJ_TYPE_BOOL 3
#define OBJ_TYPE_SYMBOL 4
#define OBJ_TYPE_LIST 5
#define OBJ_TYPE_CLOSURE 6

#define OBJ_LIST_LEN 16
#define OBJ_MAX_INT_LEN 128
#define OBJ_MAX_STRING_LEN 128
#define OBJ_HASHTABLE_LEN 256

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

#define foreach(n, l) for(size_t i = 0; i < (l).len; i++) {                     \
  __typeof(*(l).ptr) n = l.ptr[i];                                              \

#define endfor }

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

typedef struct scope_t {
  refcounted(int);
  hmap *symbols; /* hash map to store the functions associated to the symbols. */
  hmap *vars; /* variables stored here. */
  int ret;
  struct scope_t *parent; /* scopes to handle closures.*/
} scope_t;

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
    struct {
      struct obj_t *code;
      struct scope_t *scope;
    } closure; // Closure types
  };
} obj_t;

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

void error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    exit(1);
}

char *readfile(const char *filename) {
  FILE *fd = fopen(filename, "r");
  fseek(fd, 0, SEEK_END);
  long flen = ftell(fd);
  char *content = xmalloc(flen + 1);
  fseek(fd, 0, SEEK_SET);
  fread(content, flen, 1, fd);
  content[flen] = 0;
  fclose(fd);
  return content;
}

/* ======================================= Hash table ===================================== */

#define hmapIndex(m, s) hash(s) & ((m)->size - 1)
#define hmapNode(m, s) (m)->ptr[hmapIndex(m, s)]

hmap *newHmap() {
  hmap *h = xmalloc(sizeof(hmap));
  h->ptr = xmalloc(sizeof(bucket_t *) * OBJ_HASHTABLE_LEN);
  memset(h->ptr, 0, sizeof(bucket_t *) * OBJ_HASHTABLE_LEN);
  h->size = OBJ_HASHTABLE_LEN;
  h->len = 0;
  return h;
}

void freeBucket(bucket_t *node) {
  if (!node) return;
  freeBucket(node->next);
  free(node->key);
  free(node);
}

void freeHmap(hmap *m) {
  for (size_t i = 0; i < m->size; i++) freeBucket(m->ptr[i]);
  free(m->ptr);
  free(m);
}

uint32_t hash(char *string) {
  uint32_t h = 5381;
  for (char *c = string; *c; c++) h = h * 33 + *c;
  return h;
}

void *hmapGet(hmap *m, char *key) {
  for (bucket_t *n = m->ptr[hmapIndex(m, key)]; n; n = n->next)
    if (!strcmp(n->key, key)) return n->value;
  return NULL;
}

void hmapSet(hmap *m, char* key, void *value) {
  uint32_t idx = hmapIndex(m, key);
  for (bucket_t *n = m->ptr[idx]; n; n = n->next) {
    if (!strcmp(n->key, key)) { n->value = value; return; }
  }
  bucket_t *new = xmalloc(sizeof(bucket_t));
  new->key = strdup(key);
  new->value = value;
  new->next = m->ptr[idx];
  m->ptr[idx] = new;
}

/* ==================================== Object management ================================= */

void freeObj(void *ptr) {
  obj_t *self = ptr;
  if (self->type == OBJ_TYPE_LIST) {
    foreach(curr, self->l) release(curr); endfor
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

obj_t *newClosure(obj_t *code, scope_t *scope) {
  obj_t *self = newObj(OBJ_TYPE_CLOSURE);
  self->closure.code = code;
  self->closure.scope = scope;
  return self;
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
      printf("%s", o->i ? "true" : "false");
      break;
    case OBJ_TYPE_INT:
      printf("%d", o->i);
      break;
    case OBJ_TYPE_STRING:
      printf("\"%s\"", o->s.ptr);
      break;
    case OBJ_TYPE_SYMBOL:
      printf("%s", o->s.ptr);
      break;
    case OBJ_TYPE_LIST:
      printf("[");
      foreach(curr, o->l) printf(" "); print(curr); endfor
      printf(" ]");
      break;
    case OBJ_TYPE_CLOSURE:
      print(o->closure.code);
      break;
    default:
      printf("undefined");
  }
  printf("\n");
}

void freeScope(void *scope) {
  scope_t *self = scope;
  freeHmap(self->symbols);
  freeHmap(self->vars);
  free(self);
}

scope_t *newScope(scope_t *parent) {
  scope_t *scope = xmalloc(sizeof(scope_t));
  scope->parent = parent;
  scope->symbols = newHmap();
  scope->vars = newHmap();
  scope->ret = 0;
  initrefcount(scope, freeScope);
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

#define VAR_NOT_FOUND(x) error("Variable \"%s\" not found", x)

obj_t *getVar(context_t *ctx, char *name) {
  scope_t *curr = ctx->current;
  while (curr) {
    void *val = hmapGet(curr->vars, name);
    if (val) return (obj_t *)val;
    curr = curr->parent;
  }
  return NULL;
}

void setVar(context_t *ctx, char *name, obj_t *value) {
  scope_t *curr = ctx->current;
  while (curr) {
    if (hmapGet(curr->vars, name)) {
      hmapSet(curr->vars, name, value);
      return;
    }
    curr = curr->parent;
  }
  hmapSet(ctx->current->vars, name, value);
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
    } else if (peek(&parser) == '#') {
      while (peek(&parser) && peek(&parser) != '\n') consume(&parser);
      continue;
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

#define use_last(ctx, code) obj_t *last = pop((ctx)->stack->l);           \
  obj_t *res = code;                                                      \
  release(last);                                                          \
  return res;

#define BINARY_OP(name, op, type)                                         \
obj_t *name(context_t *ctx) {                                             \
    binary_params(ctx);                                                   \
    obj_t *res = type(first->i op second->i);                             \
    release(first);                                                       \
    release(second);                                                      \
    return res;                                                           \
}

obj_t *printObj(context_t *ctx) { print(pop(ctx->stack->l)); return NULL; }

/* ======================== Arithmetic operations ======================== */
BINARY_OP(plus, +, newInt)
BINARY_OP(minus, -, newInt)
BINARY_OP(division, /, newInt)
BINARY_OP(mul, *, newInt)
BINARY_OP(bitShiftLeft, <<, newInt)
BINARY_OP(bitShiftRight, >>, newInt)

/* ========================== Binary operations ========================== */
BINARY_OP(consumeAnd, &&, newBool)
BINARY_OP(consumeOr, ||, newBool)
BINARY_OP(consumeGE, >, newBool)
BINARY_OP(consumeLE, <, newBool)
BINARY_OP(consumeGTE, >=, newBool)
BINARY_OP(consumeLTE, <=, newBool)
BINARY_OP(consumeEQ, ==, newBool)

obj_t *consumeNot(context_t *ctx) { use_last(ctx, newBool(!last->i)) }

/* ========================== Stack operations =========================== */
obj_t *dup(context_t *ctx) { return copy(top(ctx->stack->l)); }
obj_t *drop(context_t *ctx) { pop(ctx->stack->l); return NULL; }
obj_t *swap(context_t *ctx) { binary_params(ctx); push(ctx->stack->l, second); push(ctx->stack->l, first); return NULL; }

/* ============================ Control flows ============================ */
obj_t *consumeIf(context_t *ctx) {
  obj_t *branch = pop(ctx->stack->l);
  obj_t *condition = pop(ctx->stack->l);
  if (condition->i) {
    exec(ctx, branch->closure.code);
  }
  release(branch);
  release(condition);
  return NULL;
}

obj_t *consumeIfElse(context_t *ctx) {
  obj_t *fbranch = pop(ctx->stack->l);
  obj_t *tbranch = pop(ctx->stack->l);
  obj_t *condition = pop(ctx->stack->l);
  exec(ctx, condition->i ? tbranch : fbranch);
  release(fbranch);
  release(tbranch);
  release(condition);
  return NULL;
}

obj_t *consumeLoop(context_t *ctx) {
  obj_t *branch = pop(ctx->stack->l);
  obj_t *condition = pop(ctx->stack->l);

  while (1) {
    exec(ctx, condition->closure.code);
    obj_t *result = pop(ctx->stack->l);
    int should_conitnue = result->i;
    release(result);
    if (!should_conitnue) break;
    exec(ctx, branch->closure.code);
  }

  release(branch);
  release(condition);
  return NULL;
}

obj_t *consumeRet(context_t *ctx) { ctx->current->ret = 1; return NULL; }

/* =========================== List operations ============================ */
obj_t *consumeListPush(context_t *ctx) { binary_params(ctx); push(first->l, second); return first; }
obj_t *consumeListPop(context_t *ctx) { pop(top(ctx->stack->l)->l); return NULL; }
obj_t *consumeListLen(context_t *ctx) { return newInt(top(ctx->stack->l)->l.len); }
obj_t *consumeListEval(context_t *ctx) { exec(ctx, top(ctx->stack->l)); return NULL; }
obj_t *consumeListSet(context_t *ctx) {
  obj_t *value = pop(ctx->stack->l);
  obj_t *index = pop(ctx->stack->l);
  obj_t *list = pop(ctx->stack->l);
  list->l.ptr[index->i] = value;
  return NULL;
}
obj_t *consumeListGet(context_t *ctx) { binary_params(ctx); return first->l.ptr[second->i]; }

obj_t *consumeInclude(context_t *ctx) {
  obj_t *last = pop(ctx->stack->l);
  char *file = readfile(last->s.ptr);
  obj_t *parsed = compile(file);
  free(file);
  foreach(block, parsed->l)
    push(ctx->stack->l, block);
  endfor
  release(last);
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
  hmapSet(ctx->current->symbols, "<<", newfunc(bitShiftLeft, 2));
  hmapSet(ctx->current->symbols, ">>", newfunc(bitShiftRight, 2));

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
  hmapSet(ctx->current->symbols, "ret", newfunc(consumeRet, 0));

  /* ===== IO Operations ====== */
  hmapSet(ctx->current->symbols, ".", newfunc(printObj, 1));

  /* ==== List operations ===== */
  hmapSet(ctx->current->symbols, "push", newfunc(consumeListPush, 2));
  hmapSet(ctx->current->symbols, "pop", newfunc(consumeListPop, 1));
  hmapSet(ctx->current->symbols, "len", newfunc(consumeListLen, 1));
  hmapSet(ctx->current->symbols, "eval", newfunc(consumeListEval, 1));
  hmapSet(ctx->current->symbols, "set", newfunc(consumeListSet, 3));
  hmapSet(ctx->current->symbols, "get", newfunc(consumeListGet, 2));

  /* ==== Module operations === */
  hmapSet(ctx->current->symbols, "include", newfunc(consumeInclude, 1));
}

int consumeVariables(context_t *ctx, obj_t *o) {
  if (o->s.len == 0) return 0;
  obj_t *val = getVar(ctx, o->s.ptr + 1);
  if (*o->s.ptr == ':') {
    obj_t *last = pop(ctx->stack->l);
    if (last->type == OBJ_TYPE_LIST) {
      retain(ctx->current);
      retain(last);
      printf("Closure captured %s\n", o->s.ptr);
      last = newClosure(last, ctx->current);
    }
    setVar(ctx, o->s.ptr + 1, last);
  } else if (*o->s.ptr == '@') {
    if (!val) VAR_NOT_FOUND(o->s.ptr + 1);
    retain(val);
    push(ctx->stack->l, val);
  } else if (*o->s.ptr == '!') {
    if (!val) VAR_NOT_FOUND(o->s.ptr);
    if (val->type == OBJ_TYPE_CLOSURE) {
      scope_t *scope = ctx->current;
      ctx->current = val->closure.scope;
      exec(ctx, val->closure.code);
      ctx->current = scope;
    } else if (val->type == OBJ_TYPE_LIST) exec(ctx, val); 
    else error("Expected a list object for %s, found %d\n", o->s.ptr + 1, val->type);
  }
  else return 0;
  return 1;
}

int consumeSymbol(context_t *ctx, obj_t *o) {
  func_t *sym = getFunc(ctx, o->s.ptr);
  if (!sym) return 0;
  if (ctx->stack->l.len < (size_t)sym->arity) {
    error("Expected at least %d element(s), found %d for symbol %s", sym->arity, ctx->stack->l.len, o->s.ptr);
  }
  obj_t *(*func)(context_t *) = sym->func;
  obj_t *result = func(ctx);
  if (result) push(ctx->stack->l, result);
  return 1;
}

void exec(context_t *ctx, obj_t *list) {
  ctx->current = newScope(ctx->current);
  if (!ctx->current->parent) {
    print(list);
  }
  foreach(o, list->l)
    if (ctx->current->ret) break;
    if (o->type == OBJ_TYPE_SYMBOL) {
      if (consumeVariables(ctx, o)) continue;
      if (!consumeSymbol(ctx, o)) error("Symbol \"%s\" not found", o->s.ptr);
    } 
    else if (o->type == OBJ_TYPE_LIST && ctx->current->parent != NULL) {
      retain(o);
      retain(ctx->current);
      obj_t *closure = newClosure(o, ctx->current);
      push(ctx->stack->l, closure);
    }
    else {
      retain(o);
      push(ctx->stack->l, o);
    }
  endfor
  scope_t *scope = ctx->current;
  ctx->current = ctx->current->parent;
  release(scope);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage %s <filename>\n", *argv);
    return 1;
  }

  char *prgtext = readfile(argv[1]);

  context_t *ctx = newContext();
  loadSymbols(ctx);
  obj_t *parsed = compile(prgtext);
  exec(ctx, parsed);
}
