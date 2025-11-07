# Simil Forth Language Guide

A minimal stack-based concatenative language where code is data.

## Basics

**Stack operations** - Everything works on a stack (like an RPN calculator):
```forth
5           # Push 5 onto stack
3           # Push 3 onto stack
+           # Pop 3 and 5, push 8
.           # Pop and print: int(8)
```

**Arithmetic:**
```forth
10 5 -      # 10 - 5 = 5
6 7 *       # 6 * 7 = 42
20 4 /      # 20 / 4 = 5
```

## Variables

**Store, load, and execute:**
```forth
42 :x       # Store 42 in variable x
@x .        # Load x and print: int(42)

[2 *] :double    # Store a function (list) in variable 'double'
5 !double .      # Execute double: 5 * 2 = 10
```

**Operators:**
- `:name` - store top of stack into variable
- `@name` - load variable onto stack
- `!name` - execute variable (must be a list)

## Lists (Code as Data)

Lists are code that can be passed around:
```forth
[3 +]       # Push a list onto the stack (doesn't execute)
5 swap      # Stack: [3 +] 5
            # Now: 5 [3 +]
```

## Comparisons & Logic

**Comparisons** (return 0 or 1):
```forth
5 3 >       # 1 (true)
5 3 <       # 0 (false)
5 5 ==      # 1 (true)
5 3 >=      # 1 (true)
```

**Boolean operators:**
```forth
1 1 and     # 1 (true AND true)
0 1 or      # 1 (false OR true)
1 not       # 0 (NOT true)
```

## Control Flow

**if** - execute list if condition is true:
```forth
5 3 > [42 .] if     # Prints int(42) because 5 > 3
5 3 < [42 .] if     # Does nothing
```

**ifelse** - execute one of two branches:
```forth
5 3 > [100 .] [200 .] ifelse    # Prints int(100)
```

**loop** - repeat while condition is false:
```forth
0 :i
[@i 5 <]                   # Condition: i < 5
[@i . @i 1 + :i]          # Body: print i, increment
loop
# Prints: 0 1 2 3 4
```

## Stack Manipulation

```forth
dup         # Duplicate top: 5 -> 5 5
drop        # Remove top: 5 3 -> 5
swap        # Swap top two: 5 3 -> 3 5
```

## Complete Examples

**Square function:**
```forth
[dup *] :square
5 !square .         # Prints int(25)
```

**Factorial (recursive):**
```forth
[
  dup 1 ==
  [drop 1]
  [dup 1 - !fact *]
  ifelse
] :fact

5 !fact .           # Prints int(120)
```

**Count to 10:**
```forth
[1 :i]
[@i 10 >]
[@i . @i 1 + :i]
loop
```

**Conditional greeting:**
```forth
[1] :happy
@happy [100 .] [0 .] ifelse    # Prints int(100)
```

