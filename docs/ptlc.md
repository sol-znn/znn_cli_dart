# PTLC commands

The `ptlc.*` commands drive the `ptlc` embedded contract of go-zenon `dev`
(checked against `ac16bfd`, reclaim lock included) through
[znn_sdk_dart](https://github.com/sol-znn/znn_sdk_dart/tree/ptlc-v2), whose
`doc/ptlc.md` describes the contract. Nothing here talks to a counterparty:
the two parties of a swap run these commands in turn and pass each other the
values they print.

## Commands

Contract calls (need a wallet):

| Command | Does |
|---|---|
| `ptlc.create tokenStandard amount expirationTime pointType pointLock [destination]` | Lock `amount` for `expirationTime` hours (1 to 168). Type 2 needs a destination. |
| `ptlc.createWithReclaimLock tokenStandard amount expirationTime pointType pointLock destination reclaimPointType reclaimPointLock reclaimProof [adaptorPoint]` | Lock until the unix time `expirationTime`, reclaimable only with a signature under the reclaim lock. |
| `ptlc.unlock id [witness]` | Unlock to this wallet. Without a witness the wallet signs when the lock is its own Ed25519 key. |
| `ptlc.proxyUnlock id destination witness` | Unlock to another address. |
| `ptlc.reclaim id [reclaimSignature]` | Take an expired entry back. An entry with a reclaim lock needs the signature. |
| `ptlc.monitor id [reclaimSignature]` | Watch an entry until it closes. Prints the witness or reclaim signature that closed it; reclaims for its creator at expiry. |

Reading the chain:

| Command | Does |
|---|---|
| `ptlc.get id` | An entry, and its reclaim lock if it has one. |
| `ptlc.inspect blockHash` | Decode a ptlc call. |
| `ptlc.message id destination pointType` | The unlock message a key must sign. |
| `ptlc.sign id destination secretKey [pointType]` | Sign it with an Ed25519 (0) or BIP-340 (1, default) key. |
| `ptlc.reclaimMessage creator destination tokenStandard amount expirationTime pointType pointLock reclaimPointType` | The reclaim message for these terms. |

Offline:

| Command | Does |
|---|---|
| `ptlc.signReclaim message secretKey [reclaimPointType]` | Sign a reclaim message. |
| `ptlc.keygen` | A secp256k1 secret, its point (type 2) and x-only key (type 1). |
| `ptlc.point secret` | The point and key of a secret. |
| `ptlc.tweak point tweak`, `ptlc.tweakSecret secret tweak` | Add a tweak. |
| `ptlc.adaptorSign secretKey message adaptorPoint` | A BIP-340 adaptor pre-signature. |
| `ptlc.adaptorVerify publicKey message adaptorPoint preSignature` | Check one. |
| `ptlc.adaptorComplete preSignature secret` | Complete it into a signature. |
| `ptlc.adaptorExtract preSignature signature` | Recover the secret from both. |

Every input is checked the way the contract checks it before anything is
published, and a witness or reclaim signature is verified locally first. An
unlock is refused with less than 60 seconds left on the chain's clock: an
unlock confirmed after the expiry is rejected, but its witness is public.

## Reclaim lock

`ptlc.createWithReclaimLock` takes an absolute expiration because the reclaim
message covers every term, the expiration included, and the counterparty signs
it before the entry exists. It refuses to send unless `reclaimProof` verifies
for those exact terms under the reclaim lock: either a 64-byte signature, or a
65-byte BIP-340 pre-signature followed by its adaptor point. Without one the
tokens could be unlocked but never reclaimed.

The reclaim message does not cover the entry id, so a signature fits every
entry with the same terms under the same lock. The counterparty should use a
new reclaim key for each swap.

A swap where the counterparty `P` holds the reclaim key and the creator `C`
holds secret `t` with point `T`:

```sh
# C proposes terms; both run this and compare
znn-cli ptlc.reclaimMessage <C> <dest> zts1znnxxxxxxxxxxxxx9z4ulx 10 <unix exp> 1 <unlock key> 1
# P pre-signs under a fresh reclaim key
znn-cli ptlc.adaptorSign <P reclaim secret> <reclaim message> <T>
# C creates; the pre-signature is verified before sending
znn-cli ptlc.createWithReclaimLock zts1znnxxxxxxxxxxxxx9z4ulx 10 <unix exp> 1 <unlock key> <dest> 1 <P reclaim key> <pre-signature> <T>
# P checks the entry and its reclaim lock
znn-cli ptlc.get <id>
# after expiry, C completes the pre-signature and reclaims
znn-cli ptlc.adaptorComplete <pre-signature> <t>
znn-cli ptlc.reclaim <id> <signature>
# P watches, then recovers t
znn-cli ptlc.monitor <id>
znn-cli ptlc.adaptorExtract <pre-signature> <signature>
```

Plain `ptlc.reclaim id` is refused for such an entry, and an unlock before the
expiry works as on any other entry.

## Tests

`test/ptlc_test.dart` covers command registration and the helpers that decide
what is sent. The manual plans in `tests/` list every command.
