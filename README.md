# zkBTC Security

This document is the security document for the [zkBTC decentralized bridge](https://zkbtc.money), developed by [Lightec Labs](https://lightec.xyz). Follow us on [X](https://x.com/LightecXYZ).

## Product Summary

zkBTC is a ZKP-based bridge that securely bridges Bitcoin to Ethereum and all other major L1s and L2s. The basic workflow are:

* Deposit—The user sends $BTC to a designated operator address. Such a transaction is proved, and the proof is verified in an Ethereum smart contract. After successful verification, the smart contract mints $zkBTC tokens and transfers these tokens to the address supplied along with the deposit (in an `OP_RETURN` output). The smart contract will manage the newly created UTXOs from this deposit. The miner who computes the proof and submits it on the user's behalf will receive rewards.
* Use—Users can use $zkBTC tokens in any way they wish; they are equivalent to $BTC in the Ethereum ecosystem.
* Redemption—The user calls an Ethereum smart contract function to burn some $zkBTC tokens. The function will also leave some transaction logs specifying which available UTXOs will be spent. Specifically, the smart contract will choose which UTXOs to spend this time and record related information in the logs. The miner reward is delayed.
* Change and miner reward. To bring back the change UTXO and reward the miner that computes proof for redemption, another proof about the redemption transaction in Bitcoin could be provided to the smart contract.

For more information and general use, please check out our [Gitbook](https://lightec.gitbook.io/lightecxyz).

We designed zkBTC to be fully decentralized, without any central role in operating on the users' assets. To achieve such an ambitious goal, we proposed to add an `OP_ZKP` opcode to Bitcoin so that Bitcoin can verify zero-knowledge proof as spending conditions of UTXOs. This way, there are no private keys to be managed at all for the `Redemption.` To redeem back to Bitcoin, one must submit proof meeting specific criteria. Finding a ZKP scheme for `OP_ZKP` has proven difficult, yet we have a draft [here](https://github.com/opzkp/tea-horse).

Before `OP_ZKP` could be realized, we also have an alternative solution, which is to have multiple safe platforms to manage private keys such that:

* Each platform is designed to safe-keep the private key in a way that it is nearly impossible to learn the content of the private key;
* each platform only signs the redemption transaction after a successful ZKP verification;
* We can tolerate one of the platforms being cracked or failing without losing security or assets.

Please turn to later sections for more details.

## Security Architecture


### Fully On-Chain

Recent security incidents reminded us to keep the front end safe, so we are also going to deploy it on-chain.

### Circuit Cascading

In both directions, many circuits are working together. Different circuits are combined together via verification key fingerprint binding. The basic idea is to compute a `FingerPrint` to verify the key of a circuit as the identifying value. The `FingerPrint` is computed as the `MiMc` hash of the key components of the in-circuit verifying key. The [codes](https://github.com/lightec-xyz/common/blob/master/utils/fingerprint.go) could be found in the [common component](https://github.com/lightec-xyz/common/tree/master), and is excerpted below:

```golang
// FingerPrint() returns the MiMc hash of the VerifyingKey. It could be used to identify a VerifyingKey
// during recursive verification.
func InCircuitFingerPrint[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](
	api frontend.API, vk *plonk.VerifyingKey[FR, G1El, G2El]) (frontend.Variable, error) {
	var ret frontend.Variable
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return ret, err
	}

	mimc.Write(vk.BaseVerifyingKey.NbPublicVariables)
	mimc.Write(vk.CircuitVerifyingKey.Size)
	mimc.Write(vk.CircuitVerifyingKey.Generator.Limbs[:]...)

	comms := make([]kzg.Commitment[G1El], 0)
	comms = append(comms, vk.CircuitVerifyingKey.S[:]...)
	comms = append(comms, vk.CircuitVerifyingKey.Ql)
	comms = append(comms, vk.CircuitVerifyingKey.Qr)
	comms = append(comms, vk.CircuitVerifyingKey.Qm)
	comms = append(comms, vk.CircuitVerifyingKey.Qo)
	comms = append(comms, vk.CircuitVerifyingKey.Qk)
	comms = append(comms, vk.CircuitVerifyingKey.Qcp[:]...)

	for _, comm := range comms {
		el := comm.G1El
		switch r := any(&el).(type) {
		case *sw_bls12377.G1Affine:
			mimc.Write(r.X)
			mimc.Write(r.Y)
		case *sw_bls12381.G1Affine:
			mimc.Write(r.X.Limbs[:]...)
			mimc.Write(r.Y.Limbs[:]...)
		case *sw_bls24315.G1Affine:
			mimc.Write(r.X)
			mimc.Write(r.Y)
		case *sw_bw6761.G1Affine:
			mimc.Write(r.X.Limbs[:]...)
			mimc.Write(r.Y.Limbs[:]...)
		case *sw_bn254.G1Affine:
			mimc.Write(r.X.Limbs[:]...)
			mimc.Write(r.Y.Limbs[:]...)
		default:
			return ret, fmt.Errorf("unknown parametric type")
		}
	}

	mimc.Write(vk.CircuitVerifyingKey.CommitmentConstraintIndexes[:]...)

	result := mimc.Sum()

	return result, nil
}
```

### Defense in Depth

A single-factor defense might attract potential adversaries. Therefore, we designed the system with defense in depth in mind. For deposit, we rely on the ICP's Bitcoin integration to sign off on the `chain tip` and the `CheckPoint` mechanism. For redemption, two of three multi-sig also provide fault tolerance. See related sections for more details.

### Security over UX

zkBTC is designed to be fully decentralized, so there is no central role in operating the risk parameters. We have to assume the worst case and defend zkBTC against it. Therefore, the UX has to yield in case there is a conflict. For example, we require each Bitcoin deposit transaction to have a confirmation depth of at least nine instead of six. There are many more such examples throughout this document.

Third-party services could enhance UX since zkBTC is designed to be fully decentralized. The basic idea is for the third-party service to deposit to the zkBTC system, obtain some zkBTC tokens, and later provide those tokens to users with better UX. Of course, third parties are free to define their business models. 

## Audit Reports


## Securing Deposits

### Defense in Depth - Overall Design

We have designed three defenses against potential attacks, layered in depth:

* `DepositTxCircuit.SigVerif` checks if the `chain tip` (the latest block hash) is signed by a `DFinity` canister. This is the initial implementation of our long-term security design of decentralized roles signing off the `chain tip`.
* The `Transaction Depth` check demands that each deposit transaction have a certain confirmation depth. Note that the commonly recommended depth of `6` is based on on-chain verification, while in our system, it is essentially an off-chain verification. Therefore, we require at least `9` for small deposits and even deeper for large deposits.
* The `CheckPoint Depth` check demands that the enclosing block for each transaction is one of the descendants of a certain recognized `CheckPoint` (also a Bitcoin block hash).

Now, assuming some potent attacker commanding lots of hashing power has already cracked the first defense, the decentralized roles to sign off the chain tip. It still has to manage enough checkpoint depth. The attacker won't be able to meet both the `Transaction Depth` requirement and the `CheckPoint Depth` requirement if we set proper checking rules in the smart contract. Before discussing any specific rules, we must point out the obvious: it is impossible to pass all legit blocks without passing some offending blocks if the adversary indeed masters too much hashing power. Our aim here is not to reject all offending blocks but to make it as computation-intensive as possible for adversaries, such that attacking us is not economically desirable.

### CheckPoint

#### Estimating CheckPoint Depth

The smart contract must estimate the checkpoint depth on its own to determine whether the value presented in the proof is acceptable. 

In case the transaction is even deeper than the checkpoint or just rests in the checkpoint block, we simply return true for checkpoint depth checking, as the checkpoint is trusted by the smart contract. Otherwise, our first attempt is: 
```Solidity
    estimated_depth = (eth_block.timestamp - tx_block.timestamp) / 600 + (cp_depth - tx_depth);
```

We assume the Ethereum timestamp as obtained by `block.timestamp` is very close to real-time as of the contract execution ([ref](https://ethereum.stackexchange.com/questions/5927/how-would-a-miner-cope-with-a-huge-block-time)). However, since the Bitcoin transaction and its enclosing block could be generated by the adversary, its timestamp could not be trusted. As `cp_depth` could also be derived from the adversary's fork chain, it is also not reliable. 
```Solidity
    estimated_depth = (eth_block.timestamp - cp_block.timestamp) / 600;
```

Alternatively, we could compute the average interval between checkpoint and 'now' and then estimate the depth. However, this computation requires unreliable `cp_depth`.

We assume a 10-minute average block interval here. This interval is often *not* the actual case. A variation of 10% is relatively common and is handled with allowance. See the following sections.

What if the proof submission is purposefully delayed such that `eth_block.timestamp` is much later than it should have been? In that case, the `estimated_depth` would be larger than the actual value. This does the adversary no good. For the same reason, a valid deposit might be declined if the submission is delayed for too long. Fortunately, this will not happen a lot in our proving-as-mining incentive setting. Every miner will do their best to submit proof as soon as possible to earn proving rewards.

#### Checking CheckPoint Depth

Suppose the attacker has 10% of all honest hashing power combined; on average, it has to spend at least 900 minutes (15 hours) to meet the transaction depth requirement for a small amount deposit, which requires `tx_depth` to be at least 9. Meanwhile, around 90 new blocks have been mined in the Bitcoin mainnet. The attacker would find out the checkpoint depth deficit to be 81. If the attacker has 30% of all hashing power, numbers become 300 minutes, 30 new blocks, and 21 blocks of checkpoint depth deficit. 

The smart contract, however, needs to take care of block timestamp drift, proof generation time, block interval variance, time to broadcast the smart contract invocation transaction and include it in a block, etc. For example, the timestamp of any Bitcoin block might be as early as just a bit later than the median value of its past 11 blocks. That will generate 1 hour or about six blocks more than the actual depth since we use `eth_block.timestamp` to estimate the checkpoint depth. The smart contract will have to subtract 6 or more from its estimated depth so that a *legit* deposit won't be declined. We could leave some more time for various other factors, ranging from half to one hour. Thus:
```
    required_minimal_depth = estimated_depth - allowance
```

#### Setting a Proper Allowance

Specifically, we'd like to reserve 6 for the potential checkpoint timestamp error, 2 for waiting for the chain tip to be available and proof to be generated, and then 1 for every additional 4 confirmation depth requirements covering the variation of hashing power and block time.
```
    allowance = 6 + 2 + (depth - 6)/6 = 7 + depth/4
```

Therefore, for transaction confirmation depth requirements of 9, 12, 18, and 24 and the checkpoint candidate depth requirement of 36, the corresponding allowance is 10, 10, 12, 13, and 16.

#### Becoming a CheckPoint Candidate

`CheckPoint` is maintained by the Ethereum smart contract without human intervention. The hash of the enclosing block for a **deep** enough transaction could be a candidate for a new `CheckPoint`. When it is time to rotate checkpoints, the smart contract selects a random candidate. Our security does *not* depend on how random the selection process is. Instead, we impose a depth requirement for each of the candidate such that the adversary won't be able to reach without failing the checkpoint depth test. Our security architecture weighs checkpoint safety more than individual blocks or transactions. Note that the formula of `estimated_depth` already assumes that the adversary starts to mine its own blocks based on a would-be checkpoint block when it is freshly mined. Successful guessing of the next checkpoint grants no additional advantages to adversaries.

Besides the depth requirement for checkpoint candidate, we also check if the timestamp of the checkpoint block is not too far in its past or future. According to the Bitcoin consensus rules, the timestamp of the checkpoint block could be at most 2 hours in its future, resulting in some *free* depth to adversaries. We ran some checks in the circuit to prevent this free depth from becoming too many and proved a flag, which the smart contract could check. On the other hand, if the checkpoint timestamp is in its past, legit deposit might be declined. So, the circuit also checks this case and sets a flag accordingly.

What if the in-circuit check is unreliable enough (for example, the blocks we use to check the timestamp are ALL in their future), and the checkpoint candidate still carries a timestamp in its past or future that is too far away? 

Although the in-circuit check is a strong defense, we could still discuss this hypothetical case under the *Defense in Depth* principle:
```Solidity
    estimated_depth = (eth_block.timestamp - (cp_block.true_timestamp + 7200)) / 600
                    = better_estimation - free_depth;
    free_depth      = 12;
```

Note that `better_estimation` is unknown to the smart contract and is used here simply to clarify this text.

#### Free Depth from Consensus

There is another source of *free* depth besides what we have discussed so far. If there are lots of new mining power joining the game, the average block interval could be greatly shrunk.

Let's discuss a concrete yet hypothetical case, that after a checkpoint is selected only a few blocks after a new mining difficulty had been settled. Immediately after the checkpoint selectioin, some mining power joins the game just to drive the average block time to below 8 minutes instead of 10. 20 hours later, the main-net generates 150 new blocks intead of 120. The excessive 30 new blocks give the adversary a huge boost.

#### Putting Everything Together

We need to find out the threshold of hashing power that an adversary must command in order to defeat our checkpoint system. Given:
```Solidity
    estimated_depth = (eth_block.timestamp - (cp_block.true_timestamp + 7200)) / 600
                    = better_estimation - free_depth;
    free_depth      = 12;
    required_minimal_depth = estimated_depth - allowance;
    allowance = 7 + depth/4
```

Suppose the transaction depth requirement is D (D = 9 for small deposits, 12 for medium amounts, and 18 and 24 for even larger amounts), and the attacker commands x% hashing power compared to all honest miners combined. At some point on or after the checkpoint block, the attacker must begin to mine its own blocks. To meet the transaction depth requirement, the attacker must spend `average_attacker_time_for_D_blocks` on average, assuming the average block interval to be 10 minutes:
```golang
    average_attacker_time_for_D_blocks := D * 600 / (x/100) = D * 60000/x
```

Meanwhile, the mainnet keeps producing new blocks; the expected average blocks mined are:
```golang
    expected_average_blocks_mainnet := average_attacker_time_for_D_blocks / 600 = D * 100/x
```

During this period, the checkpoint depth that the attacker would obtain will lag behind that of the mainnet by `cp_depth_diff`:
```golang
    cp_depth_diff := expected_average_blocks_mainnet - D = D * (100/x - 1)
```

The attacker needs `cp_depth_diff <= allowance`. But since there could be free depth, he needs only `cp_depth_diff <= allowance + free_depth` or:
```golang
    // D * (100/x - 1) <= allowance + free_depth <--> x >= 100*D/(allowance + D + 12)
    // (allowance + D + 12) must be positive
```

Solving the above inequalities for `(D, allowance) = (9, 10)`:
```golang
    // x >= 900/(9 + 10 + 12) = 29.0
```
And for `(D, allowance) = (12, 10), (18, 12), (24, 13)`
```golang
    // x >= 1200/(12 + 10 + 12) = 35.2
    // x >= 1800/(18 + 12 + 12) = 42.8
    // x >= 2400/(24 + 13 + 12) = 49.0
```

Note that we were talking about average cases. There are small chances that the attacker mines more blocks sooner than average. However, the block time variation has been handled with the allowance value (see earlier sections).

The `tx_depth` requirement for a checkpoint candidate is set to 36 (with `allowance` set to 16):
```golang
    // x >= 3600/(36 + 16 + 12) = 56.3
```

#### Escalating the Depth Requirement

It seems not profitable to spend at least 30% of all total-net hashing power just to make a fake deposit of a small amount. The attacker, however, no double will try to stuff as many transactions as possible into one block and hope to deposit all of them successfully.

To counter this measure, we keep the count of deposit transactions per block and escalate the depth requirement once a certain limit is reached.

#### An Even More Aggressive Attacker

In the above discussion, we assume the attacker uses *new* hashing power instead of drawing the *existing* mining power to compute the attack. This way, the mainnet is generating new blocks at a relatively steady rate. However, if a very powerful attacker can turn some existing hashing power to attack zkBTC, then the rate at which the mainnet produces new blocks will be slowed down. And our analysis is impacted. This is the typical `p vs q` situation in the original [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf).

Nonetheless, our security architecture does not rely on the actual block interval. We use the expected 10 minutes and then `allowance` to handle any variation. So if the supposed situation does happen, then instead of invalid deposits being accepted, valid deposits might get declined as the checkpoint depth requirement cannot be met, but only temporarily.

To recover from this situation, the mainnet must have mined blocks faster than the 10-minute expectation to compensate for the 'lost depth'. This could happen a while after the attacker has stopped without gains, or more honest hashing power joins the mining as their owners see the opportunity or the difficulty adjustment results in a lower difficulty due to a prolonged average block interval and hence faster block mining.

### Defense in Depth - Replacing Chain Tip Signature with More Depth Requirements

In the discussion, the chain tip's signature has become the single point of failure (SPoF). That is, if, for some reason, the ICP canister cannot sign the Bitcoin tip block, then we cannot generate proof that it is acceptable to the deployed smart contract. To overcome this hurdle, we could replace the signature with more depth requirements.

Our current practice is to double the depth requirements, and update the allowance value accordingly. This is on top of the depth requirement escalation mentioned earlier.

With this design, we have two new depth requirements: (D, allowance) = (48, 19), (72, 25). The hashing power requirements for the attacker are:
```golang
    // x >= 4800/(48 + 19 + 12) = 60.8
    // x >= 7200/(72 + 25 + 12) = 66.1
```

## Securing Redemption

### The Ethereum Light Client Protocol

We use the Ethereum Light Client Protocol (LCP) to determine if the transaction to call the designated redeem function has been completed successfully and the enclosing block has been finalized. This includes the major parts:

* the transaction to call the designated redeem function has been completed successfully and left some logs as receipts;
* the transaction belongs to a block;
* the block is an ancestor of another block, which has been finalized as being signed off by a sync committee;
* there exists a signature chain from the genesis sync committee to the signing sync committee;

By proving the above assertions, we are sure that the redeem function has been executed as expected. Then, we can extract data from the proven logs, assemble a Bitcoin transaction, and send it along with the proof to be verified and signed/executed. Note that all the information needed to assemble the Bitcoin transaction, including all the available UTXOs, is managed with the smart contract. 

### opZKP

Our long-term plan is to upgrade Bitcoin to support [`OP_ZKP`](https://github.com/opzkp/tea-horse). Then, we can supply Bitcoin with the transaction (inputs, outputs) and its (segregated) witness (proof). The proof serves as the spending conditions of the input UTXOs, much like a signature in a regular Bitcoin transfer transaction. Once the verification is successful, the Bitcoin network can process the transaction, and the user will get the redeemed $BTC.

### MultiSig Design

The interim solution is to use a two-of-three multi-sig scheme. As mentioned at the beginning of this document, we need multiple safe platforms to manage private keys such that:

* Each platform is designed to safe-keep the private key in a way that it is nearly impossible to learn the content of the private key;
* Each platform only signs the redemption transaction after a successful ZKP verification;
* We can tolerate one of the platforms being cracked or failing without losing security or assets.

And our choices are:

* ICP [tECDSA](https://internetcomputer.org/docs/references/t-sigs-how-it-works/), available in a canister programmed to verify proof before signing the transaction. And the private key is never reconstructed during signing. 
* Oasis [Sapphire](https://oasisprotocol.org/sapphire), an EVM compatible L1 based on TEE technology. The Intel SGX technology used in Oasis Sapphire can protect both the private key and the integrity of the enclave code so that no one can bypass the proof verification placed before transaction signing.
* Intel SGX-enabled machines, similar to Oasis Sapphire, are operated by the Lightec team. SGX technology ensures that even the Lightec team cannot learn the private key content or bypass the "proof-verfication-before-signature" logic.

Interested readers may refer to ICP or Oasis documents for security-related information. We will cover how we program and operate the SGX enclave.

### Security of Applying SGX

For a general introduction to SGX, especially about how it could secure computation, we recommend the classic paper [Intel SGX Explained](https://eprint.iacr.org/2016/086.pdf) by Victor Costan and Srinivas Devadas. 

In a nutshell, an SGX enclave provides:

* encrypted memory content which could be decrypted only inside the CPU and visible to its owning enclave, preventing privileged OS processes or even hardware systems (BIOS, memory controller, etc.) from accessing the confidential data;
* program integrity such that once the program is tampered with, it is either an invalid or totally different enclave. In either case, it cannot decrypt any data encrypted by the original enclave.

We are building on top of [ego](https://github.com/edgelesssys/ego), a popular Golang library to use SGX. The enclave verifies a zero-knowledge proof of a redemption transaction before signing the Bitcoin transaction with a private key it manages. The private key is initially generated by the first instance of the enclave, then exported and encrypted so that only itself or another enclave with the exact binary code could decrypt inside the enclave. Put another way, even the Lightec team cannot read the content of the private key or bypass the zkp verification to obtain a signature.

Below picture outlines the interaction between client and server so that the client can retrieve the encrypted private key from server.
![zkbtc](docs/zkbtcsgx.drawio.svg)

#### Client-Server TLS Authentication
Note that the TLS connectivity between Client and Server is bi-directionally authenticated, with pinned self-signed certificates.

1.	Each of the client and server generates a TLS certificate using an Ed25519 key pair derived from the hash of its SGX Unique Key, applying SHA256 twice: `privateKey := SHA256(SHA256(UniqueKey))`
2.	The generated certificates are then distributed to the client and server.
3.	Both the client and server load their peer certificate for bi-directional authentication.

#### Secure Secret Distribution

The server should create the secret only once, and [seal](https://pkg.go.dev/github.com/edgelesssys/ego@v1.7.0/ecrypto#SealWithUniqueKey) it with its SGX Unique Key so that it could [unseal](https://pkg.go.dev/github.com/edgelesssys/ego@v1.7.0/ecrypto#Unseal) it after restarting. After that and once the secret is restored in the enclave, server is ready for the client to retrieve the secret.

Once the TLS connection is established, the secret exchange process follows these steps:

A. Client Generates an SGX Remote Attestation Report
1.	The client generates a Secp256k1 key pair, again with the private key being `privateKey := SHA256(SHA256(UniqueKey))`. Note that this might fail with a negleble chance (less than $2^{-127}$), which is acceptable in our use.
2.	The public key is used as a parameter [to generate an SGX Remote Attestation Report](https://pkg.go.dev/github.com/edgelesssys/ego@v1.7.0/enclave#GetRemoteReport).
3.	The client sends the SGX report to the server.

B. Server Verifies the Client’s Report and Encrypts the Secret
1.	The server [verifies the client’s SGX Remote Attestation Report](https://pkg.go.dev/github.com/edgelesssys/ego@v1.7.0/enclave#VerifyRemoteReport), as well as if the Enclave Unique Id matches that of its own.
2.	It extracts the client-side public key from the client’s report.
3.	The server encrypts the secret according to the `ECIES` protocol, using the extracted public key and an ephemeral key pair. The underlying symmetric cipher suite is `AES128 + HMAC-SHA-256-16`.
4.	It computes the hash of the ciphertext.
5.	The computed hash is used as a parameter to generate the server’s SGX Remote Attestation Report.
6.	The server sends the SGX report along with the ciphertext to the client.

C. Client Verifies the Server’s Report and Decrypts the Secret
1.	The client verifies the server’s SGX Remote Attestation Report, as well as if the Enclave Unique Id matches that of its own.
2.	It extracts the ciphertext hash from the server’s SGX report.
3.	The client computes the hash of the received ciphertext.
4.	It compares the computed hash with the one extracted from the server’s SGX report.
5.	If the hashes match, the client decrypts the ciphertext using its private key.
6.	Finally, the client seals the secret using its SGX Unique Key.

Our SGX code will be open once we complete the audit and launch the product.

### The BLS Signature Verification for BLS12-381 G2

The Ethereum Light Client Protocol requires this. As related library is not available when we started to develop zkBTC, we developed such circuit on our own and we had submitted a [PR to gnark](https://github.com/Consensys/gnark/pull/1040), pending audit, review and merge.

## chainark

In deposit and redemption, we need to prove a chain of relationship: for Bitcoin, the blocks are chained with double SHA256; for Ethereum Light Client Protocol, the sync committees are chained with BLS signature, etc. We developed [chainark](https://github.com/lightec-xyz/chainark) to prove a kind of chained relationship. Basically:

* a `UnitCircuit` is a user-defined circuit that makes up the chaining;
* a `RecursiveCircuit` either verifies two `UnitCircuit` proofs or one `RecursiveCircuit` or `HybridCircuit` proof immediately followed by a `UnitCircuit` proof;
* a `HybridCircuit` is similar to `RecursiveCircuit`, but instead of a `UnitCircuit` proof, it verifies the chaining conditions directly. The benefit of `HybridCircuit` over `RecursiveCircuit` is saving a recursion.

The security of chainark is, therefore, of essential importance to zkBTC. Here are the main design considerations:

* Circuit `FingerPrint` is used throughout the chainark library to identify circuits. Unlike some simple situations in which an outer circuit verifies a proof from an inner circuit and only needs the in-circuit verification key, we design the chainark to be capable of verifying a chain of any length. So, the basic idea is for the `RecursiveCircuit` or `HybridCircuit` to verify their proof (from an earlier proving session). Of course, they cannot use a verification key when its definition has not yet been finished. `FingerPrint` is the answer to this dilemma. In the source code, this is the `MultiRecursiveCircuit.SelfFps` or `HybridCircuit.SelfFps` (an array).
* For any circuit to verify if a proof from the `RecursiveCircuit` or `HybridCircuit` is acceptable, they need to verify the proof with a proper verification key and check if the recursion has been performed correctly. That is, the verification keys used to in-circuit verify other proofs must match the listed fingerprints exactly one-to-one. These listed fingerprints are used to identify which recursive or hybrid circuit could be trusted.

## System Upgradability


## Responsible Disclosure


## Open Source Plan
