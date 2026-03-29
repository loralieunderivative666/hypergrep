# Agent Instructions

This project has `hypergrep` installed. Use it instead of grep/ripgrep for code search.

## Commands

```bash
# Text search (replaces rg/grep)
hypergrep "pattern" src/

# Structural search (returns full function bodies, not lines)
hypergrep -s "pattern" src/

# Semantic search (signatures + call graph, fits in token budget)
hypergrep --layer 1 --budget 800 --json "pattern" src/

# Who calls this function?
hypergrep --callers "function_name" src/

# What breaks if I change this?
hypergrep --impact "function_name" src/

# Does this project use a technology?
hypergrep --exists "redis" src/

# Codebase overview (load once at session start)
hypergrep --model "" src/
```

## When to use what

- **Finding code**: `hypergrep --layer 1 --budget 800 --json "pattern" src/`
- **Understanding a function**: `hypergrep -s "function_name" src/`
- **Before changing code**: `hypergrep --impact "function_name" src/`
- **Start of session**: `hypergrep --model "" src/`
- **Checking dependencies**: `hypergrep --exists "library_name" src/`
