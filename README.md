# Simil Forth interpreter

It is a very simple and minimal language stack-based that uses the postfix notation.

## Syntax
### Stack ops and arithmetic

5 3 + / + takes the 2 last elements in the stack, sum them and append the result in the stack
7 2 - . / dot is used to print the last element in the stack

## Stack-based ops

2 dup . / DUP op duplicate the last element and push to the stack
1 swap .
3 over .
rot .
