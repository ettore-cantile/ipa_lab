#!/usr/bin/env python3
"""
p1_c_eval.py -- evaluate Pipeline 1's inference from the C it compiles.

Why this exists
---------------
A synthetic scenario has two integer implementations of the same model:

  synth.reference.forward_int8   Python; writes expected.json
  ebpf_program (P1)              C literals, compiled into the kernel

Each can be consistent with itself and still disagree with the other. Until
2026-09-23 they did: generate.py called the reference without `scale`, so
expected.json left the bias of layer l unscaled, while the generator multiplied
it by scale**l. Every userspace test compared the reference with itself, and
the only comparison against the datapath needed Linux, root and BCC.

This module closes that gap without a kernel. It reads the generated source
and evaluates the model function's inference section -- feature reads, dense
layers, argmax -- with C's integer rules: fixed widths, the usual arithmetic
conversions, division truncating toward zero, RELU_LL expanded from its own
#define. The numbers come from the literals in the text, never from the weight
list, so a generator that emits a wrong multiplier gives a wrong answer here.

What it does NOT cover: clang, the verifier, the JIT, and the packet path
around the inference (parsing, TTL check, redirect). verify_synth_kernel.py
runs the compiled program for that. A statement outside the subset below is an
error, never skipped, so a generator change cannot pass unnoticed; so is
signed overflow, which C leaves undefined, BPF wraps and the Python reference
never does.

The subset: declarations (scalar and pointer), assignment, blocks, if/else,
switch/case/break, map `.lookup(&key)`, `*p`, `p->field`, `a[i]`, casts,
unary - ! * &, binary * / + - < > <= >= == != & && ||, and ?: .
"""

import re


class CEvalError(Exception):
    """The source left the evaluated subset, or did something C leaves
    undefined (signed overflow, division by zero, NULL dereference)."""


# ---------------------------------------------------------------------------
# integer types
# ---------------------------------------------------------------------------
_INT = {"u8": (8, False), "u16": (16, False), "u32": (32, False),
        "u64": (64, False), "s32": (32, True), "s64": (64, True)}

# C spellings accepted in declarations and casts
_SPELLING = {("__u8",): "u8", ("__u16",): "u16", ("__u32",): "u32",
             ("__u64",): "u64", ("__s32",): "s32", ("int",): "s32",
             ("__s64",): "s64", ("long", "long"): "s64",
             ("unsigned", "int"): "u32", ("unsigned",): "u32",
             ("unsigned", "long", "long"): "u64"}
_TYPE_WORDS = {w for k in _SPELLING for w in k} | {"struct"}


def _fit(v, t, what):
    """`v` as a value of type `t`. Unsigned wraps, as C defines; signed out of
    range raises, because C leaves it undefined and the reference never wraps."""
    bits, signed = _INT[t]
    if signed:
        if -(1 << (bits - 1)) <= v < (1 << (bits - 1)):
            return v
        raise CEvalError(f"{what}: {v} overflows {t} (undefined in C, wraps in "
                         f"BPF, never wraps in the Python reference)")
    return v & ((1 << bits) - 1)


def _promote(t):
    return "s32" if _INT[t][0] < 32 else t


def _common(a, b):
    """The usual arithmetic conversions, for the types above."""
    a, b = _promote(a), _promote(b)
    if a == b:
        return a
    (ba, sa), (bb, sb) = _INT[a], _INT[b]
    if sa == sb:
        return a if ba >= bb else b
    u, s = (b, a) if sa else (a, b)
    # a signed type wider than the unsigned one represents all its values
    return u if _INT[u][0] >= _INT[s][0] else s


def _literal(tok):
    """An integer constant with the type C gives it (BPF: long is 64-bit)."""
    m = re.fullmatch(r"(0[xX][0-9a-fA-F]+|\d+)([uU]?)((?:ll|LL)?)([uU]?)", tok)
    if not m or (m.group(2) and m.group(4)):
        raise CEvalError(f"integer literal {tok!r} outside the evaluated forms")
    digits, u1, ll, u2 = m.groups()
    hexa = digits[:2].lower() == "0x"
    if not hexa and len(digits) > 1 and digits[0] == "0":
        raise CEvalError(f"octal literal {tok!r} not evaluated")
    v = int(digits, 16) if hexa else int(digits)
    unsigned = bool(u1 or u2)
    if ll:
        cands = ["u64"] if unsigned else (["s64", "u64"] if hexa else ["s64"])
    elif unsigned:
        cands = ["u32", "u64"]
    else:
        cands = ["s32", "u32", "s64", "u64"] if hexa else ["s32", "s64"]
    for t in cands:
        bits, signed = _INT[t]
        if v < (1 << (bits - 1 if signed else bits)):
            return (v, t)
    raise CEvalError(f"literal {tok} does not fit any integer type")


# ---------------------------------------------------------------------------
# text -> tokens (comments stripped, function-like macros expanded)
# ---------------------------------------------------------------------------
_TOKEN = re.compile(r"""
    \s+
  | (?P<num>0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*)
  | (?P<id>[A-Za-z_]\w*)
  | (?P<op>->|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^!~<>?:;,.(){}\[\]=])
""", re.X)


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _tokenize(text):
    out, pos = [], 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise CEvalError(f"cannot tokenize near {text[pos:pos + 40]!r}")
        pos = m.end()
        if m.lastgroup:
            out.append((m.lastgroup, m.group(m.lastgroup)))
    return out


_DEFINE = re.compile(r"^[ \t]*#define[ \t]+(\w+)\((\w+)\)[ \t]+(.+?)[ \t]*$", re.M)


def _macros(src):
    """One-parameter function-like macros defined in `src`, e.g. RELU_LL."""
    out = {}
    for name, param, body in _DEFINE.findall(src):
        toks = _tokenize(_strip_comments(body))
        if name in out and out[name] != (param, toks):
            raise CEvalError(f"macro {name} defined twice with different bodies")
        out[name] = (param, toks)
    return out


def _expand(tokens, macros, hide=frozenset()):
    """Substitute macro calls token by token, as the preprocessor does: the
    argument is expanded first, the result rescanned with the macro hidden."""
    out, i = [], 0
    while i < len(tokens):
        kind, val = tokens[i]
        if (kind == "id" and val in macros and val not in hide
                and i + 1 < len(tokens) and tokens[i + 1] == ("op", "(")):
            param, body = macros[val]
            depth, j, arg = 1, i + 2, []
            while True:
                if j >= len(tokens):
                    raise CEvalError(f"unterminated call of macro {val}")
                t = tokens[j]
                if t == ("op", "("):
                    depth += 1
                elif t == ("op", ")"):
                    depth -= 1
                    if depth == 0:
                        break
                elif t == ("op", ",") and depth == 1:
                    raise CEvalError(f"macro {val} takes one argument")
                arg.append(t)
                j += 1
            arg = _expand(arg, macros, hide)
            sub = []
            for bt in body:
                sub.extend(arg if bt == ("id", param) else [bt])
            out.extend(_expand(sub, macros, hide | {val}))
            i = j + 1
            continue
        out.append(tokens[i])
        i += 1
    return out


# ---------------------------------------------------------------------------
# tokens -> tree
# ---------------------------------------------------------------------------
_BINARY = {"||": 1, "&&": 2, "&": 5, "==": 6, "!=": 6,
           "<": 7, ">": 7, "<=": 7, ">=": 7, "+": 9, "-": 9, "*": 10, "/": 10}


class _Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def done(self):
        return self.i >= len(self.t)

    def peek(self, k=0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else (None, None)

    def where(self):
        return " ".join(v for _, v in self.t[max(0, self.i - 6): self.i + 6])

    def expect(self, op):
        if self.peek() != ("op", op):
            raise CEvalError(f"expected {op!r} near: {self.where()}")
        self.i += 1

    def ident(self):
        k, v = self.peek()
        if k != "id":
            raise CEvalError(f"expected an identifier near: {self.where()}")
        self.i += 1
        return v

    # -- types --------------------------------------------------------------
    def is_type(self, k=0):
        kind, val = self.peek(k)
        return kind == "id" and val in _TYPE_WORDS

    def type_words(self):
        if self.peek() == ("id", "struct"):
            self.i += 1
            return ("struct", self.ident())
        words = []
        while self.is_type() and self.peek()[1] != "struct":
            words.append(self.peek()[1])
            self.i += 1
        t = _SPELLING.get(tuple(words))
        if t is None:
            raise CEvalError(f"type {' '.join(words)!r} not evaluated")
        return t

    # -- expressions --------------------------------------------------------
    def expr(self):
        c = self.binary(1)
        if self.peek() == ("op", "?"):
            self.i += 1
            a = self.expr()
            self.expect(":")
            return ("?:", c, a, self.expr())
        return c

    def binary(self, min_prec):
        lhs = self.unary()
        while True:
            kind, val = self.peek()
            prec = _BINARY.get(val) if kind == "op" else None
            if prec is None or prec < min_prec:
                if kind == "op" and val in ("<<", ">>", "|", "^", "%"):
                    raise CEvalError(f"operator {val!r} not evaluated")
                return lhs
            self.i += 1
            lhs = ("bin", val, lhs, self.binary(prec + 1))

    def unary(self):
        kind, val = self.peek()
        if kind == "op" and val in ("-", "!", "*", "&"):
            self.i += 1
            return ("un", val, self.unary())
        if (kind, val) == ("op", "(") and self.is_type(1):
            self.i += 1
            t = self.type_words()
            if self.peek() == ("op", "*"):
                raise CEvalError(f"pointer cast not evaluated near: {self.where()}")
            self.expect(")")
            return ("cast", t, self.unary())
        return self.postfix()

    def postfix(self):
        e = self.primary()
        while True:
            val = self.peek()[1] if self.peek()[0] == "op" else None
            if val in ("->", "."):
                self.i += 1
                e = ("member", e, self.ident(), val == "->")
            elif val == "[":
                self.i += 1
                idx = self.expr()
                self.expect("]")
                e = ("index", e, idx)
            elif val == "(":
                self.i += 1
                args = []
                if self.peek() != ("op", ")"):
                    args.append(self.expr())
                    while self.peek() == ("op", ","):
                        self.i += 1
                        args.append(self.expr())
                self.expect(")")
                e = ("call", e, args)
            else:
                return e

    def primary(self):
        kind, val = self.peek()
        if kind == "num":
            self.i += 1
            return ("num", _literal(val))
        if kind == "id":
            self.i += 1
            return ("var", val)
        if (kind, val) == ("op", "("):
            self.i += 1
            e = self.expr()
            self.expect(")")
            return e
        raise CEvalError(f"expression expected near: {self.where()}")

    # -- statements ---------------------------------------------------------
    def statement(self):
        kind, val = self.peek()
        if (kind, val) == ("op", "{"):
            self.i += 1
            body = []
            while self.peek() != ("op", "}"):
                if self.done():
                    raise CEvalError("unterminated block")
                body.append(self.statement())
            self.i += 1
            return ("block", body)
        if (kind, val) == ("op", ";"):
            self.i += 1
            return ("empty",)
        if (kind, val) == ("id", "if"):
            self.i += 1
            self.expect("(")
            cond = self.expr()
            self.expect(")")
            then = self.statement()
            other = None
            if self.peek() == ("id", "else"):
                self.i += 1
                other = self.statement()
            return ("if", cond, then, other)
        if (kind, val) == ("id", "switch"):
            self.i += 1
            self.expect("(")
            ctl = self.expr()
            self.expect(")")
            self.expect("{")
            items = []
            while self.peek() != ("op", "}"):
                if self.done():
                    raise CEvalError("unterminated switch")
                if self.peek() == ("id", "case"):
                    self.i += 1
                    label = self.expr()
                    self.expect(":")
                    items.append(("case", label))
                elif self.peek() == ("id", "default"):
                    self.i += 1
                    self.expect(":")
                    items.append(("default",))
                else:
                    items.append(self.statement())
            self.i += 1
            return ("switch", ctl, items)
        if (kind, val) == ("id", "break"):
            self.i += 1
            self.expect(";")
            return ("break",)
        if self.is_type():
            base = self.type_words()
            decls = []
            while True:
                ptr = False
                if self.peek() == ("op", "*"):
                    self.i += 1
                    ptr = True
                name = self.ident()
                init = None
                if self.peek() == ("op", "="):
                    self.i += 1
                    init = self.expr()
                decls.append((name, "ptr" if ptr else base, init))
                if self.peek() == ("op", ","):
                    self.i += 1
                    continue
                self.expect(";")
                return ("decl", decls)
        if kind == "id" and self.peek(1) == ("op", "="):
            self.i += 2
            e = self.expr()
            self.expect(";")
            return ("assign", val, e)
        raise CEvalError(f"statement outside the evaluated subset near: {self.where()}")


# ---------------------------------------------------------------------------
# tree -> values
# ---------------------------------------------------------------------------
class _Ptr:
    __slots__ = ("obj",)

    def __init__(self, obj):
        self.obj = obj                      # None is NULL


class _Cell:
    __slots__ = ("val",)

    def __init__(self, val):
        self.val = val


class _Map:
    """A BPF map as the program sees it through `.lookup(&key)`.

    ARRAY: every key below max_entries exists, zero-filled unless given.
    HASH: only the given keys exist; anything else is NULL.
    """

    def __init__(self, name, kind, vtype, n, given, vec_sizes):
        self.name, self.kind, self.vtype, self.n = name, kind, vtype, n
        if isinstance(given, (list, tuple)):
            given = {0: list(given)}        # a vector map: its single entry
        self.given = dict(given or {})
        self.vec_sizes = vec_sizes

    def _value(self, raw):
        m = re.fullmatch(r"struct\s+(\w+)", self.vtype)
        if m:
            size = self.vec_sizes.get(m.group(1))
            if size is None:
                raise CEvalError(f"map {self.name}: value {self.vtype} not modelled")
            raw = [0] * size if raw is None else list(raw)
            if len(raw) != size:
                raise CEvalError(f"map {self.name}: {len(raw)} values given, "
                                 f"the source declares {size}")
            return {"v": [(_fit(int(x), "u32", self.name), "u32") for x in raw]}
        t = _SPELLING.get(tuple(self.vtype.split()))
        if t is None:
            raise CEvalError(f"map {self.name}: value {self.vtype} not modelled")
        return _Cell((_fit(int(raw or 0), t, self.name), t))

    def lookup(self, key):
        if self.kind == "array":
            if not 0 <= key < self.n:
                return _Ptr(None)
            return _Ptr(self._value(self.given.get(key)))
        if key not in self.given:
            return _Ptr(None)
        return _Ptr(self._value(self.given[key]))


class _Break(Exception):
    pass


class _Env:
    def __init__(self, base):
        self.scopes = [dict(base)]

    def push(self):
        self.scopes.append({})

    def pop(self):
        self.scopes.pop()

    def slot(self, name):
        for sc in reversed(self.scopes):
            if name in sc:
                return sc[name]
        raise CEvalError(f"identifier {name!r} is not declared in the "
                         f"evaluated section")

    def declare(self, name, t, v):
        if name in self.scopes[-1]:
            raise CEvalError(f"{name} declared twice in one scope")
        self.scopes[-1][name] = [t, v]


def _truth(v):
    return v.obj is not None if isinstance(v, _Ptr) else v[0] != 0


def _convert(v, t, what):
    if t == "ptr":
        if not isinstance(v, _Ptr):
            raise CEvalError(f"{what}: integer assigned to a pointer")
        return v
    if isinstance(t, tuple):
        raise CEvalError(f"{what}: struct by value not evaluated")
    if not isinstance(v, tuple):
        raise CEvalError(f"{what}: non-integer assigned to {t}")
    return (_fit(v[0], t, what), t)


def _binop(op, a, b):
    if not (isinstance(a, tuple) and isinstance(b, tuple)):
        raise CEvalError(f"operator {op} on a non-integer")
    t = _common(a[1], b[1])
    x, y = _fit(a[0], t, op), _fit(b[0], t, op)
    if op in ("<", ">", "<=", ">=", "==", "!="):
        r = {"<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y,
             "==": x == y, "!=": x != y}[op]
        return (int(r), "s32")
    if op == "+":
        r = x + y
    elif op == "-":
        r = x - y
    elif op == "*":
        r = x * y
    elif op == "/":
        if y == 0:
            raise CEvalError("division by zero")
        q = abs(x) // abs(y)                # C: truncation toward zero
        r = q if (x < 0) == (y < 0) else -q
    elif op == "&":
        r = x & y
    else:
        raise CEvalError(f"operator {op!r} not evaluated")
    return (_fit(r, t, f"{x} {op} {y}"), t)


def _eval(e, env):
    k = e[0]
    if k == "num":
        return e[1]
    if k == "var":
        v = env.slot(e[1])[1]
        if v is None:
            raise CEvalError(f"{e[1]} read before it is assigned")
        return v
    if k == "bin":
        op = e[1]
        if op in ("&&", "||"):
            left = _truth(_eval(e[2], env))
            if (op == "&&" and not left) or (op == "||" and left):
                return (int(left), "s32")
            return (int(_truth(_eval(e[3], env))), "s32")
        return _binop(op, _eval(e[2], env), _eval(e[3], env))
    if k == "?:":
        # Both arms are evaluated to know the result type; the subset has no
        # side effects, and the only ?: the generator emits (RELU_LL) has the
        # condition's own operand and 0LL as its arms.
        cond = _truth(_eval(e[1], env))
        a, b = _eval(e[2], env), _eval(e[3], env)
        if isinstance(a, tuple) and isinstance(b, tuple):
            t = _common(a[1], b[1])
            v = a if cond else b
            return (_fit(v[0], t, "?:"), t)
        raise CEvalError("?: over pointers not evaluated")
    if k == "un":
        op, v = e[1], None
        if op == "&":
            if e[2][0] != "var":
                raise CEvalError("& of a non-variable not evaluated")
            return _Ptr(_Cell(_eval(e[2], env)))
        v = _eval(e[2], env)
        if op == "!":
            return (int(not _truth(v)), "s32")
        if op == "*":
            if not isinstance(v, _Ptr):
                raise CEvalError("* of a non-pointer")
            if v.obj is None:
                raise CEvalError("NULL dereference")
            if not isinstance(v.obj, _Cell):
                raise CEvalError("* of a struct pointer not evaluated")
            return v.obj.val
        if not isinstance(v, tuple):
            raise CEvalError("unary - of a pointer")
        t = _promote(v[1])
        return (_fit(-_fit(v[0], t, "-"), t, "unary -"), t)
    if k == "cast":
        v = _eval(e[2], env)
        return _convert(v, e[1], "cast")
    if k == "member":
        base = _eval(e[1], env)
        if e[3]:                            # ->
            if not isinstance(base, _Ptr):
                raise CEvalError(f"-> on a non-pointer ({e[2]})")
            if base.obj is None:
                raise CEvalError(f"NULL dereference (->{e[2]})")
            base = base.obj
        if isinstance(base, _Map):
            if e[2] != "lookup":
                raise CEvalError(f"map method {e[2]} not evaluated")
            return ("method", base)
        if not isinstance(base, dict) or e[2] not in base:
            raise CEvalError(f"no field {e[2]!r}")
        return base[e[2]]
    if k == "index":
        arr, idx = _eval(e[1], env), _eval(e[2], env)
        if not isinstance(arr, list) or not isinstance(idx, tuple):
            raise CEvalError("[] on a non-array")
        if not 0 <= idx[0] < len(arr):
            raise CEvalError(f"index {idx[0]} out of bounds ({len(arr)})")
        return arr[idx[0]]
    if k == "call":
        fn = _eval(e[1], env)
        if not (isinstance(fn, tuple) and fn[0] == "method") or len(e[2]) != 1:
            raise CEvalError("only map.lookup(&key) calls are evaluated")
        key = _eval(e[2][0], env)
        if not isinstance(key, _Ptr) or not isinstance(key.obj, _Cell):
            raise CEvalError("lookup() takes the address of a key")
        return fn[1].lookup(key.obj.val[0])
    raise CEvalError(f"expression node {k!r} not evaluated")


def _exec(s, env):
    k = s[0]
    if k == "decl":
        for name, t, init in s[1]:
            v = None if init is None else _convert(_eval(init, env), t, name)
            env.declare(name, t, v)
    elif k == "assign":
        slot = env.slot(s[1])
        slot[1] = _convert(_eval(s[2], env), slot[0], s[1])
    elif k == "block":
        env.push()
        try:
            for st in s[1]:
                _exec(st, env)
        finally:
            env.pop()
    elif k == "if":
        if _truth(_eval(s[1], env)):
            _exec(s[2], env)
        elif s[3] is not None:
            _exec(s[3], env)
    elif k == "switch":
        ctl = _eval(s[1], env)
        if not isinstance(ctl, tuple):
            raise CEvalError("switch on a non-integer")
        t = _promote(ctl[1])
        items = s[2]
        start = None
        for idx, it in enumerate(items):
            if it[0] == "case" and _fit(_eval(it[1], env)[0], t, "case") == ctl[0]:
                start = idx
                break
        if start is None:
            start = next((idx for idx, it in enumerate(items)
                          if it[0] == "default"), None)
        if start is None:
            return
        env.push()
        try:
            for it in items[start:]:        # C falls through until break
                if it[0] not in ("case", "default"):
                    _exec(it, env)
        except _Break:
            pass
        finally:
            env.pop()
    elif k == "break":
        raise _Break()
    elif k != "empty":
        raise CEvalError(f"statement {k!r} not evaluated")


# ---------------------------------------------------------------------------
# the P1 model function
# ---------------------------------------------------------------------------
_ARRAY = re.compile(r"\bBPF_ARRAY\(\s*(\w+)\s*,\s*([^,()]+?)\s*,\s*(\d+)\s*\)")
_HASH = re.compile(r"\bBPF_HASH\(\s*(\w+)\s*,\s*([^,()]+?)\s*,\s*([^,()]+?)\s*,"
                   r"\s*(\d+)\s*\)")
_VEC = re.compile(r"\bstruct\s+(\w+)\s*\{\s*__u32\s+v\[(\d+)\];\s*\}")

# The generator's own comments bound the section: the first opens the input
# vector, the second opens the class dispatch that follows the argmax.
_START = "/* Input vector built locally"
_END = "/* --- class -> action"


class P1Program:
    """The inference section of one `model_<id>` in a generated P1 source.

    Parsed once; `run()` evaluates it for one packet. Inputs are what the
    datapath reads: the packet TTL, the ingress ifindex, and map contents --
    a list for a vector map (its entry 0), a {key: value} dict otherwise.
    """

    def __init__(self, src, model_id=0):
        head = f"int model_{model_id}(struct xdp_md *ctx) {{"
        a = src.find(head)
        if a < 0:
            raise CEvalError(f"model_{model_id} is not in the source")
        start = src.find(_START, a)
        end = src.find(_END, start)
        nxt = src.find("\nint model_", a + len(head))
        if start < 0 or end < 0 or (nxt != -1 and nxt < end):
            raise CEvalError(f"inference section of model_{model_id} not "
                             f"found between {_START!r} and {_END!r}: the "
                             f"generator changed layout, update p1_c_eval")
        decls = _strip_comments(src)
        self.macros = _macros(decls)
        self.maps = {n: ("array", vt, int(c)) for n, vt, c in _ARRAY.findall(decls)}
        self.maps.update({n: ("hash", vt, int(c))
                          for n, _kt, vt, c in _HASH.findall(decls)})
        self.vec_sizes = {n: int(c) for n, c in _VEC.findall(decls)}

        raw = _tokenize(_strip_comments(src[start:end]))
        self.used_macros = sorted({v for k, v in raw
                                   if k == "id" and v in self.macros})
        p = _Parser(_expand(raw, self.macros))
        self.body = []
        while not p.done():
            self.body.append(p.statement())
        outs = sorted(int(n[4:]) for s in self.body if s[0] == "decl"
                      for n, _t, _i in s[1] if re.fullmatch(r"out_\d+", n))
        if not outs or outs != list(range(len(outs))):
            raise CEvalError(f"output declarations out_0..out_N not found ({outs})")
        self.n_out = len(outs)

    def run(self, ttl, maps=None, ingress_ifindex=1):
        """Logits and chosen class for one packet, as the C computes them."""
        if not 0 <= int(ttl) <= 255:
            raise ValueError(f"ttl {ttl} is not a byte")
        maps = dict(maps or {})
        unknown = set(maps) - set(self.maps)
        if unknown:
            raise CEvalError(f"maps {sorted(unknown)} are not declared by "
                             f"this source")
        base = {"ip": ["ptr", _Ptr({"ttl": (int(ttl), "u8")})],
                "ctx": ["ptr", _Ptr({"ingress_ifindex":
                                     (_fit(int(ingress_ifindex), "u32", "ifindex"),
                                      "u32")})]}
        for name, (kind, vt, n) in self.maps.items():
            base[name] = ["map", _Map(name, kind, vt, n, maps.get(name),
                                      self.vec_sizes)]
        env = _Env(base)
        env.push()                          # the function's own scope
        try:
            for s in self.body:
                _exec(s, env)
        except _Break:
            raise CEvalError("break outside a switch")
        scope = env.scopes[1]
        logits = [scope[f"out_{k}"][1][0] for k in range(self.n_out)]
        if "best_cls" not in scope:
            raise CEvalError("best_cls not declared: argmax section missing")
        return {"logits": logits, "cls": scope["best_cls"][1][0]}
