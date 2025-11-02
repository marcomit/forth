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

#define retain(x) if (x) (x)->refcount++                                       \

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

/* ==================================== Object structure ===================== */
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
} obj_t;

typedef struct context_t {
  obj_t *stack;
  obj_t *bstack;
  int bdepth;
  obj_t *vars;
} context_t;

typedef struct parser_t {
  char *program;
  char *current;
} parser_t;

obj_t *compile(char *);
 void exec(obj_t *);

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

context_t *newContext() {
  context_t *ctx = xmalloc(sizeof(context_t *));
  ctx->stack = newList();
  ctx->bstack = newList();
  ctx->bdepth = 0;
  // ctx->vars;
  return ctx;
}

/* ======================================= Turn program into list ==============================*/

#define consume(parser) (parser)->current++
#define peek(parser) *(parser)->current

void parseSpaces(parser_t *parser) {
  while (peek(parser) && isspace(*parser->current)) consume(parser);
}

obj_t *parseInt(parser_t *parser) {
  char *start = parser->current;
  if (peek(parser) == '-') consume(parser);
  while (peek(parser) && isdigit(*parser->current)) consume(parser);
  size_t len = parser->current - start;
  if (len == 0 || len > 128) return NULL;
  char buff[128];
  memcpy(buff, start, len + 1);
  return newInt(atoi(buff));
}

obj_t *parseSymbol(parser_t *parser) {
  char *start = parser->current;
  while (peek(parser) && isalnum(*parser->current)) consume(parser);
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

// obj_t *parseTuple(parser_t *parser) {
//   if (*parser->current != '(') return NULL;
//   consume(parser);
//   char *start = parser->current;
//   int level = 1;
//   while (peek(parser) && level > 0) {
//     if (peek(parser) == '(') level++;
//     else if (peek(parser) == ')') level--;
//     consume(parser);
//   }
//   size_t len = parser->current - start - 1;
//   char buff[len+1];
//   memcpy(buff, start, len);
//   buff[len] = 0;
//   obj_t *list = compile(buff);
//   list->type = OBJ_TYPE_TUPLE;
//   return list;
// }

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
    if (peek(&parser) == '-' || isdigit(peek(&parser))) {
      o = parseInt(&parser);
    }
    else if (peek(&parser) == '"') {
      o = parseString(&parser);
    }
    else if (peek(&parser) == '[') {
      o = parseList(&parser);
    }
    // else if (*parser.current == '(') {
    //   o = parseTuple(&parser);
    // }
    else {
      o = parseSymbol(&parser);
    }
    if (o) append(parsed, o);
    else printf("Error parsing near %s ...\n", start);
  }

  return parsed;
}

/* ================================ Executing the object ================================ */

void consumeObject(context_t *ctx, obj_t *o) {

}

void exec(obj_t *list) {
  context_t *ctx = newContext();
  print(list);
  for (size_t i = 0; i < list->l.len; i++) {
    obj_t *curr = list->l.ptr[i];

  }
}


int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: %s <filename>\n", argv[0]);
    printf("In the future you can start the forth interpreter in REPL mode\n");
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
  exec(parsed);
}
