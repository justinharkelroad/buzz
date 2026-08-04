import type { UserSearchResult } from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";

/** Persona/card sharing is intentionally people-only. User search can return a
 * relay-directory agent with `isAgent: false` when its OA owner proof is
 * missing or invalid, so classification must include relay and local agent
 * identities and must settle before any recipient is actionable. */
export function filterPeopleShareRecipients(
  users: readonly UserSearchResult[],
  {
    isClassificationPending,
    managedAgentPubkeys,
    relayAgentPubkeys,
  }: {
    isClassificationPending: boolean;
    managedAgentPubkeys: ReadonlySet<string>;
    relayAgentPubkeys: ReadonlySet<string>;
  },
) {
  if (isClassificationPending) return [];
  return users.filter((user) => {
    const pubkey = normalizePubkey(user.pubkey);
    return (
      !user.isAgent &&
      !managedAgentPubkeys.has(pubkey) &&
      !relayAgentPubkeys.has(pubkey)
    );
  });
}
