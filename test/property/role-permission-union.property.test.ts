/**
 * Property-Based Test: Role Permission Union (Property 11)
 *
 * Validates that in OR mode, access is granted if the user has ANY role
 * from the required set. A user with multiple roles has the union of all
 * their roles' permissions.
 *
 * Invariant (OR mode): user_roles ∩ required_roles ≠ ∅ → access granted
 *
 * Tagged: Feature: externalId, Property 11: Role Permission Union
 * Validates: Requirements 10.1, 10.3, 10.4
 */
import * as fc from 'fast-check';

// ─────────────────────────────────────────────────────────────────────────────
// Role matching logic (mirrors the library's SecuredCloudFront behavior)
// ─────────────────────────────────────────────────────────────────────────────

enum RoleMatchMode {
  OR = 'OR',   // Any matching role grants access
  AND = 'AND', // ALL required roles must be present
}

/**
 * Check if a user's roles satisfy the required roles for a route.
 * Mirrors the role check in auth-check.js.
 *
 * @param userRoles - Roles in the user's JWT claims
 * @param requiredRoles - Roles required for the route
 * @param mode - OR (any match) or AND (all must match)
 * @returns true if access is granted
 */
function checkRoleAccess(
  userRoles: string[],
  requiredRoles: string[],
  mode: RoleMatchMode,
): boolean {
  if (requiredRoles.length === 0) {
    return true; // No roles required → open access
  }

  if (mode === RoleMatchMode.OR) {
    // User needs at least ONE of the required roles
    return requiredRoles.some((required) => userRoles.includes(required));
  }

  if (mode === RoleMatchMode.AND) {
    // User needs ALL of the required roles
    return requiredRoles.every((required) => userRoles.includes(required));
  }

  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Arbitraries
// ─────────────────────────────────────────────────────────────────────────────

// Role GUIDs (like the AppRole values in the CDN stack)
const roleArb = fc.uuid();
const roleArrayArb = fc.uniqueArray(roleArb, { minLength: 1, maxLength: 5 });

// ─────────────────────────────────────────────────────────────────────────────
// Property tests
// ─────────────────────────────────────────────────────────────────────────────

describe('Property 11: Role Permission Union (OR mode)', () => {
  it('user with at least one matching role is always granted access (200 iterations)', () => {
    fc.assert(
      fc.property(
        roleArrayArb, // required roles for the route
        roleArrayArb, // additional non-matching roles the user might have
        fc.integer({ min: 0 }), // which required role the user has
        (requiredRoles, extraRoles, pickIndex) => {
          // Guarantee the user has at least one of the required roles
          const matchingRole = requiredRoles[pickIndex % requiredRoles.length];
          const userRoles = [...extraRoles, matchingRole];

          const granted = checkRoleAccess(userRoles, requiredRoles, RoleMatchMode.OR);
          expect(granted).toBe(true);
        }
      ),
      { numRuns: 200 }
    );
  });

  it('user with NO matching roles is always denied access (200 iterations)', () => {
    fc.assert(
      fc.property(
        roleArrayArb, // required roles
        roleArrayArb, // user roles (guaranteed disjoint by filtering)
        (requiredRoles, candidateUserRoles) => {
          // Filter user roles to ensure NO overlap with required
          const requiredSet = new Set(requiredRoles);
          const userRoles = candidateUserRoles.filter((r) => !requiredSet.has(r));

          // Skip if filtering eliminated all user roles (rare with UUIDs)
          fc.pre(userRoles.length > 0 || candidateUserRoles.length === 0);

          const granted = checkRoleAccess(userRoles, requiredRoles, RoleMatchMode.OR);
          expect(granted).toBe(false);
        }
      ),
      { numRuns: 200 }
    );
  });

  it('empty required roles array → always granted (open route)', () => {
    fc.assert(
      fc.property(roleArrayArb, (userRoles) => {
        const granted = checkRoleAccess(userRoles, [], RoleMatchMode.OR);
        expect(granted).toBe(true);
      }),
      { numRuns: 100 }
    );
  });

  it('user with ALL required roles is granted (superset of minimum)', () => {
    fc.assert(
      fc.property(roleArrayArb, (requiredRoles) => {
        // User has every required role (and possibly more)
        const userRoles = [...requiredRoles, 'extra-role-bonus'];
        const granted = checkRoleAccess(userRoles, requiredRoles, RoleMatchMode.OR);
        expect(granted).toBe(true);
      }),
      { numRuns: 100 }
    );
  });
});

describe('Property 11: Role Permission Union (AND mode)', () => {
  it('user with ALL required roles is granted access (100 iterations)', () => {
    fc.assert(
      fc.property(roleArrayArb, (requiredRoles) => {
        const userRoles = [...requiredRoles]; // exact match
        const granted = checkRoleAccess(userRoles, requiredRoles, RoleMatchMode.AND);
        expect(granted).toBe(true);
      }),
      { numRuns: 100 }
    );
  });

  it('user missing any one required role is denied in AND mode (100 iterations)', () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(roleArb, { minLength: 2, maxLength: 5 }),
        fc.integer({ min: 0 }),
        (requiredRoles, removeIndex) => {
          // User has all required roles except one
          const userRoles = [...requiredRoles];
          userRoles.splice(removeIndex % userRoles.length, 1);

          const granted = checkRoleAccess(userRoles, requiredRoles, RoleMatchMode.AND);
          expect(granted).toBe(false);
        }
      ),
      { numRuns: 100 }
    );
  });
});

describe('Role access: ADMIN fallback pattern', () => {
  const ADMIN_ROLE = 'admin-guid-8de8bfc7';
  const SUPPORT_ROLE = 'support-guid-placeholder';
  const MARKETING_ROLE = 'marketing-guid-placeholder';

  it('ADMIN always has access to support routes (OR mode with ADMIN in required)', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(SUPPORT_ROLE, MARKETING_ROLE),
        (specificRole) => {
          // Route requires [specificRole, ADMIN_ROLE] in OR mode
          const requiredRoles = [specificRole, ADMIN_ROLE];
          const adminUser = [ADMIN_ROLE];

          expect(checkRoleAccess(adminUser, requiredRoles, RoleMatchMode.OR)).toBe(true);
        }
      ),
      { numRuns: 50 }
    );
  });

  it('non-admin without the specific role is denied', () => {
    const requiredRoles = [SUPPORT_ROLE, ADMIN_ROLE];
    const marketingUser = [MARKETING_ROLE]; // Has marketing, not support or admin

    expect(checkRoleAccess(marketingUser, requiredRoles, RoleMatchMode.OR)).toBe(false);
  });
});
