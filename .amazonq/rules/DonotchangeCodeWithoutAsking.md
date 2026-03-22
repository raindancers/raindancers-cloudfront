# Code Change Workflow

You MUST follow this exact workflow for ANY code change:

1. **STOP** - Do not write any code yet
2. **ANALYZE** - Understand the requirement fully
3. **PRESENT** - Show 2-3 options with pros/cons for each
4. **ASK** - End with: "Which option would you like me to implement?"
5. **WAIT** - Do not proceed until user explicitly chooses an option
6. **IMPLEMENT** - Only after explicit approval

If you skip steps 3-5, you have violated this rule.

## Code Change Authorization

Before using fsWrite, fsReplace, or executeBash to modify code:
- You MUST present options with relevant pros and cons
- You MUST wait for user to say one of these trigger phrases:
  - "implement option X"
  - "do option X"
  - "go ahead with X"
  - "make that change"
  - "yes, do that"

Without these trigger phrases, DO NOT modify code.

## Important Principles

- Do not try to implement 'easy' options just because we can't make something work
- We must properly exhaust all options before choosing
- Never assume the user wants immediate implementation
- Always present trade-offs, even for "obvious" solutions
- **Prioritize proper solutions over quick fixes** - we want fixes that resolve the root cause, not convenient workarounds
- **Avoid band-aid solutions** - temporary fixes that mask problems are not acceptable
- **Think long-term** - consider maintainability, scalability, and technical debt
- **Question convenience** - if a solution seems "easy" or "quick", examine whether it actually solves the problem
- **Validate against documentation** - when making choices about approaches, verify facts against official documentation before presenting options

## Examples

### ❌ WRONG:
```
User: "Add error handling"
AI: *immediately uses fsReplace to add try/catch*
```

### ✅ CORRECT:
```
User: "Add error handling"
AI: "Here are 3 approaches:

Option 1: Try/catch blocks
- Pros: Simple, familiar pattern
- Cons: Broad error catching, can hide bugs

Option 2: Result types (Result<T, Error>)
- Pros: Explicit error handling, type-safe
- Cons: More verbose, requires refactoring

Option 3: Error boundary pattern
- Pros: Clean separation, centralized handling
- Cons: Requires architectural changes

Which option would you like me to implement?"

User: "Do option 1"
AI: *now uses fsReplace*
```

### ❌ WRONG:
```
User: "The function is slow"
AI: *immediately adds caching without discussing options*
```

### ✅ CORRECT:
```
User: "The function is slow"
AI: "Here are optimization options:

Option 1: Add memoization/caching
- Pros: Quick win, no algorithm changes
- Cons: Memory overhead, stale data risk

Option 2: Optimize the algorithm
- Pros: Better long-term solution, no memory overhead
- Cons: Requires analysis, more complex

Option 3: Move to async/background processing
- Pros: Better UX, doesn't block
- Cons: Architectural change, complexity

Which approach would you prefer?"
```