This folder contains an implementation of the Ed25519 digital signature algorithms. The top-level routines are to be integrated into AWS-LC, so their interfaces are designed to satisfy the requirements from AWS-LC. In particular, the `private_key` mentioned here should contain the initial random seed appended with the public key derived from the seed, which is a design decision in AWS-LC for better performance.

ed25519.S: The implementation in ARM64 assembly.

_internal_s2n_bignum.h: header file included in ed25519.S.

ed25519.o: the object file obtained by assembling ed25519.S on an EC2 instance with the instance type c7g.16xlarge and the Amazon Linux operating system. See compilation_pipeline.md for the command.

disassembly.txt: the disassembly of ed25519.o.

ed25519_s2n_bignum.h: header file containing the interface of the top-level Ed25519 routines implemented in ed25519.S.

ed25519_pseudocode_specs.md: pseudocode of the specifications for all the Ed25519 subroutines, including the auxiliary ones.

ed25519_s2n_bignum_test.c: test harness testing the implementation against the Ed25519 test vectors in RFC 8032. See compilation_pipeline.md for how to compile and run the test.

Final integration plan.md: pseudocode implementation of Ed25519 subroutines, pseudocode showing how the top-level routines should be integrated into AWS-LC, and pseudocode specifications of the top-level routines.