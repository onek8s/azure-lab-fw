// Package azure provides the credential chain, a minimal ARM client
// (paging via nextLink, retries with backoff and Retry-After, structured
// errors), a Key Vault secret client and IMDS instance metadata (PLAN §6.1).
//
// All ARM payloads are returned as raw JSON (json.RawMessage) so that
// internal/policy can decode them with its own structs and detect unknown
// fields. FetchPolicyChain returns policies ordered root base policy first,
// leaf policy last; together with FetchIPGroups and FetchServiceTags it
// yields exactly the pieces of the file-source document (PLAN §4.1):
// policies, ruleCollectionGroups keyed by policy ID, ipGroups, serviceTags.
package azure
