# Documentation Rules

Follow these rules when creating or updating documentation in this project.

## Document Placement

### Architecture Decision Records (ADRs)
**Location:** `/docs/adr/`

**When to create:**
- Making architectural decisions (authentication, database choice, security policies)
- Decisions that are difficult to reverse
- Decisions with significant trade-offs
- Decisions that affect multiple teams or components

**Naming:** `ADR-{kebab-case-title}.md`

**Required sections:**
- Status (PROPOSED/ACCEPTED/REJECTED/DEPRECATED/SUPERSEDED)
- Context (problem, constraints, requirements)
- Decision (what was chosen and how it works)
- Consequences (benefits, trade-offs, impacts)

**Example:** `ADR-oauth-authorization-code-flow.md`

### Implementation Plans
**Location:** `/docs/implementation/todo/` (move to `/docs/implementation/completed/` when done)

**When to create:**
- Step-by-step implementation guides
- Feature development plans
- Migration plans

**Required sections:**
- Status (PLANNED/IN PROGRESS/COMPLETE)
- Objectives
- Implementation Steps (with verification)
- Success Criteria
- Rollback Plan

**Naming:** `{feature-name}-implementation-plan.md`

### Architecture Documentation
**Location:** `/docs/architecture/`

**When to create:**
- System architecture overviews
- Design patterns and technical specifications
- Service integration documentation
- Security architecture models

**Examples:** `zero-trust-architecture.md`, `dynamodb-security-architecture.md`

### Reference Documentation
**Location:** `/docs/reference/`

**When to create:**
- Technical specifications
- Security considerations
- Feature documentation
- API references
- Configuration guides

**Examples:** `securityConsiderations.md`, `cookieSecurity.md`

### Testing Documentation
**Location:** `/docs/testing/`

**When to create:**
- Testing strategies and guides
- Test case documentation
- Security testing procedures

**Examples:** `cloudfront-functions-testing-guide.md`, `security-testing-guide.md`

### User Guides
**Location:** `/docs/guides/`

**When to create:**
- End-user documentation
- Developer usage guides
- Getting started guides

**Example:** `usage-guide.md`

### Queries & Scripts
**Location:** `/docs/queries/`

**When to create:**
- SQL queries for analysis
- Utility scripts
- Operational runbooks

**Example:** `athena-incident-lookup.sql`

### Ideas & Brainstorming
**Location:** `/docs/ideas.md`

**When to add:**
- Future feature ideas
- Experimental concepts
- Architectural explorations not yet decided

## Writing Style

### Be Concise
- Use clear, direct language
- Avoid unnecessary verbosity
- Get to the point quickly

### Use Structure
- Use headings to organize content
- Use bullet points for lists
- Use code blocks for examples
- Use diagrams for complex flows

### Include Examples
- Provide code examples where relevant
- Show before/after comparisons
- Include command-line examples with expected output

### Link Related Documents
- Reference related ADRs
- Link to implementation plans
- Cross-reference architecture docs
- Use relative paths: `../adr/ADR-name.md`

### Status Indicators
Use consistent status markers:
- ✅ COMPLETE
- 🚧 IN PROGRESS
- 📋 PLANNED
- 💡 PROPOSED
- ❌ REJECTED

## Document Maintenance

### When Implementation Completes
Move from `/docs/implementation/todo/` to `/docs/implementation/completed/`

### When ADR Status Changes
Update the Status section (PROPOSED → ACCEPTED, ACCEPTED → DEPRECATED, etc.)

### When Superseding an ADR
- Mark old ADR as SUPERSEDED with link to new ADR
- Create new ADR with reference to superseded decision

### Update Main README
When adding significant documentation, update `/docs/README.md` to include it in the index.

## Cross-References

### From Implementation Plans
```markdown
**Related ADR:** [ADR-feature-name.md](../adr/ADR-feature-name.md)
```

### From Reference Docs
```markdown
See [Architecture Overview](../architecture/system-architecture.md) for details.
```

### From ADRs
```markdown
**Supersedes:** [ADR-old-approach.md](./ADR-old-approach.md)
```

## Templates

### ADR Template
```markdown
# ADR: {Title}

## Status
{PROPOSED/ACCEPTED/REJECTED/DEPRECATED/SUPERSEDED}

## Context
{Problem, constraints, requirements}

## Decision
{What was decided and how it works}

## Consequences
✅ {Benefits}
❌ {Trade-offs}

## Alternatives Considered
- {Alternative 1}: {Why rejected}
```

### Implementation Plan Template
```markdown
# {Feature} Implementation Plan

## Status
{PLANNED/IN PROGRESS/COMPLETE}

## Objectives
- {Goal 1}
- {Goal 2}

## Implementation Steps

### Step 1: {Title}
**Actions:** {What to do}
**Verification:** {How to verify}

## Success Criteria
- [ ] {Criterion 1}
- [ ] {Criterion 2}

## Rollback Plan
{How to revert if needed}
```

## Don'ts

- Don't create documentation for trivial decisions
- Don't duplicate information across multiple documents
- Don't use absolute file paths in cross-references
- Don't leave documents in `/todo/` indefinitely
- Don't create documents without clear purpose
- Don't write implementation details in ADRs (put in implementation plans)
- Don't write architectural decisions in implementation plans (put in ADRs)
- Don't use emojis or special characters in filenames (use them inside documents only)

## Filename Conventions

**Allowed characters:**
- Letters: `a-z`, `A-Z`
- Numbers: `0-9`
- Hyphens: `-`
- Underscores: `_`
- Periods: `.`

**Examples:**
- ✅ `ADR-oauth-authorization-code-flow.md`
- ✅ `jwt-validation-implementation-plan.md`
- ✅ `zero-trust-architecture.md`
- ❌ `✅-completed-feature.md` (no emojis)
- ❌ `my feature.md` (no spaces, use hyphens)
- ❌ `feature@v2.md` (no special chars except `-`, `_`, `.`)
