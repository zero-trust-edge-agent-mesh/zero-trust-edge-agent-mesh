---- MODULE EdgePolicyCRDT ----
EXTENDS Naturals, FiniteSets

CONSTANTS Replicas, Ops, MaxClock
VARIABLES seen, revoked, allowed, clock, partitioned

vars == <<seen, revoked, allowed, clock, partitioned>>

Init ==
  /\ seen = [r \in Replicas |-> {}]
  /\ revoked = [r \in Replicas |-> FALSE]
  /\ allowed = [r \in Replicas |-> TRUE]
  /\ clock = [r \in Replicas |-> 0]
  /\ partitioned = {}

CanDeliver(src, dst) == src # dst /\ {src, dst} \notin partitioned /\ {dst, src} \notin partitioned

AddAllow(r, op) ==
  /\ op \in Ops \ {"revoke"}
  /\ clock[r] < MaxClock
  /\ seen' = [seen EXCEPT ![r] = @ \cup {op}]
  /\ revoked' = revoked
  /\ allowed' = [allowed EXCEPT ![r] = ~revoked[r]]
  /\ clock' = [clock EXCEPT ![r] = @ + 1]
  /\ partitioned' = partitioned

Revoke(r) ==
  /\ clock[r] < MaxClock
  /\ seen' = [seen EXCEPT ![r] = @ \cup {"revoke"}]
  /\ revoked' = [revoked EXCEPT ![r] = TRUE]
  /\ allowed' = [allowed EXCEPT ![r] = FALSE]
  /\ clock' = [clock EXCEPT ![r] = @ + 1]
  /\ partitioned' = partitioned

Deliver(src, dst) ==
  /\ CanDeliver(src, dst)
  /\ ~(seen[src] \subseteq seen[dst])
  /\ clock[dst] < MaxClock
  /\ seen' = [seen EXCEPT ![dst] = @ \cup seen[src]]
  /\ revoked' = [revoked EXCEPT ![dst] = @ \/ revoked[src]]
  /\ allowed' = [allowed EXCEPT ![dst] = ~revoked'[dst]]
  /\ clock' = [clock EXCEPT ![dst] = @ + 1]
  /\ partitioned' = partitioned

Partition(a, b) ==
  /\ a # b
  /\ {a, b} \notin partitioned /\ {b, a} \notin partitioned
  /\ partitioned' = partitioned \cup {{a, b}}
  /\ UNCHANGED <<seen, revoked, allowed, clock>>

Heal(a, b) ==
  /\ {a, b} \in partitioned \/ {b, a} \in partitioned
  /\ partitioned' = partitioned \ {{a, b}, {b, a}}
  /\ UNCHANGED <<seen, revoked, allowed, clock>>

Next ==
  \/ \E r \in Replicas: \E op \in Ops: AddAllow(r, op)
  \/ \E r \in Replicas: Revoke(r)
  \/ \E src \in Replicas: \E dst \in Replicas: Deliver(src, dst)
  \/ \E a \in Replicas: \E b \in Replicas: Partition(a, b)
  \/ \E a \in Replicas: \E b \in Replicas: Heal(a, b)

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ seen \in [Replicas -> SUBSET Ops]
  /\ revoked \in [Replicas -> BOOLEAN]
  /\ allowed \in [Replicas -> BOOLEAN]
  /\ clock \in [Replicas -> 0..MaxClock]
  /\ partitioned \subseteq SUBSET Replicas

RevocationSafety == \A r \in Replicas: revoked[r] => allowed[r] = FALSE
SeenRevokeSafety == \A r \in Replicas: "revoke" \in seen[r] => allowed[r] = FALSE
DenyWins == \A r \in Replicas: ("revoke" \in seen[r]) => ~("allowA" \in seen[r] /\ allowed[r])
====
