// -----------------------------------------------------------------------------
// Reserved-substrings list.
//
// This in-repo constant IS the canonical reserved-substrings list the validator
// consumes. It is kept in-repo (not fetched at runtime) because the list is
// short and rarely changes; a network dependency is not worth introducing.
//
// When the list changes, edit this constant directly. The validator
// parametrizes on it so tests pull from the same source.
// -----------------------------------------------------------------------------

export const RESERVED_SUBSTRINGS: readonly string[] = ["cinatra"];
