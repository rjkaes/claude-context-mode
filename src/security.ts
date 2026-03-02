// ==============================================================================
// Types
// ==============================================================================

export type PermissionDecision = "allow" | "deny" | "ask";

export interface SecurityPolicy {
  allow: string[];
  deny: string[];
  ask: string[];
}

// ==============================================================================
// Pattern Parsing
// ==============================================================================

/**
 * Extract the glob from a Bash permission pattern.
 * "Bash(sudo *)" returns "sudo *", "Read(.env)" returns null.
 */
export function parseBashPattern(pattern: string): string | null {
  // .+ is greedy: for "Bash(echo (foo))" it captures "echo (foo)"
  // because $ forces the final \) to match only the last paren.
  const match = pattern.match(/^Bash\((.+)\)$/);
  return match ? match[1] : null;
}

// ==============================================================================
// Glob-to-Regex Conversion
// ==============================================================================

/** Escape all regex special characters (including *). */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\\/\-]/g, "\\$&");
}

/** Escape regex specials except *, then convert * to .* */
function convertGlobPart(glob: string): string {
  return glob
    .replace(/[.+?^${}()|[\]\\\/\-]/g, "\\$&")
    .replace(/\*/g, ".*");
}

/**
 * Convert a Bash permission glob to a regex.
 *
 * Two formats:
 * - Colon: "tree:*" becomes /^tree(\s.*)?$/ (command with optional args)
 * - Space: "sudo *" becomes /^sudo .*$/  (literal glob match)
 */
export function globToRegex(
  glob: string,
  caseInsensitive: boolean = false,
): RegExp {
  let regexStr: string;

  const colonIdx = glob.indexOf(":");
  if (colonIdx !== -1) {
    // Colon format: "command:argsGlob"
    const command = glob.slice(0, colonIdx);
    const argsGlob = glob.slice(colonIdx + 1);
    const escapedCmd = escapeRegex(command);
    const argsRegex = convertGlobPart(argsGlob);
    // Match command alone OR command + space + args
    regexStr = `^${escapedCmd}(\\s${argsRegex})?$`;
  } else {
    // Plain glob: "sudo *", "ls*", "* commit *"
    regexStr = `^${convertGlobPart(glob)}$`;
  }

  return new RegExp(regexStr, caseInsensitive ? "i" : "");
}

/**
 * Check if a command matches any Bash pattern in the list.
 * Returns the matching pattern string, or null.
 */
export function matchesAnyPattern(
  command: string,
  patterns: string[],
  caseInsensitive: boolean = false,
): string | null {
  for (const pattern of patterns) {
    const glob = parseBashPattern(pattern);
    if (!glob) continue;
    if (globToRegex(glob, caseInsensitive).test(command)) return pattern;
  }
  return null;
}
