# NTI-VATE Recovery Mapping (Proposed)


This document records the proposed mapping and expected outcomes for the joint NTI-VATE lost-response recovery trial (Issue #64).


## Identifier Mapping


*   **Logical Operation:** The signed NTI `action_payload.action_id` identifies the logical operation.
*   **Per-Attempt Token:** The signed NTI `nonce` acts as a per-attempt token for this fixture, mapping to the original VATE `attempt_id` recorded in the receiver's test context.
*   **Idempotency:** The NTI `recovery.idempotency_key` remains tied to the logical operation.


The recovery identifiers must agree with this mapping.


## Verification Context


*   **NTI Receipt:** Verify the native payload digest and signature against the pinned test key. Preserve its digest basis separately from VATE's request digest. The receipt is additional evidence; it does not replace the original VATE admission.
*   **DID/Delegation Authorization:** This remains a separate, unchecked input unless the trial explicitly supplies those checks (Layer 0).
*   **Later Outcome:** Use the existing provider's recovered history, checked under the fixed test context, as the separate evidence of completion. The receiving application supplies that observation; VATE evaluates its linkage to the original operation and attempt.


## Expected Outcomes


**None of these outcomes authorises a fresh execution. This first case tests recovery of the original result.**


| Evidence received | Expected receiving-side result |
| :--- | :--- |
| Valid NTI receipt only | Keep the execution outcome unknown/unresolved. |
| Matching, trusted provider evidence of completion | Record completion against the original attempt, retaining the earlier unknown observation. |
| Different operation/attempt or inconsistent identifiers | Reject the linkage and preserve the original state. |
| No response, or a lookup returns "not found" | Keep the outcome unresolved; absence alone does not establish nonexecution. |
