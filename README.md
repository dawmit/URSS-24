# Elliptic Curve Implementation of J-PAKE

## Overview

J-PAKE (Password Authenticated Key Exchange Protocol by Juggling) is a protocol developed by Feng Hao and Peter Ryan [1].
It allows for the establishment of secure communication between two parties with just a shared password, and without the use of Public Key Infrastructure. It uses a different approach to the well known pattented PAKE's such as EKE and SPEKE, achieving certain security advantages over the current
PAKE's without the losses in efficiency common with more secure protocols. 

This repository is a JAVA implementation of J-PAKE using Elliptic Curve Cryptography to 
generate the keys and is officially included in the Bouncy Caslte API. An equivalent J-PAKE implementation exists in Bouncy Castle, however it uses Finite Multiplicative Groups to generate the session keys which is much more computationally expensive when compared to using Elliptic Curves.

## Advantages

The original finite multiplicative group implementation of J-PAKE must use group parameters with much longer bit-lengths to achieve security strength equivalent to the elliptic curve version. 

For example, to achieve a maximum of 256-bit security strength using finite multiplicative groups, you would need at least 2048-bit parameters (specifically for the prime modulus parameter), whereas for EC (elliptic curve) to achieve 256-bit strength you need approximately a 512-bit prime field
to define the curve over. This is a large difference in size, which siginificantly decreases the cost of computation. Moreover, the protocol itself works more efficiently with elliptic curves, where there are only 11 total multiplications being computed. Whereas using finite
multiplicative groups the protocol uses 14 modular exponentiations to generate the final session key [3].

## Chosen Elliptic Curves

There are only 3 curves included in the implementation: those being the NIST P256, P384 and P512 [2]. In the future I plan to add more curves and different types of curves.

## Installation

To install and use this implementation, go to the official Bouncy Castle github [4] and follow their build/install guide. You can treat Bouncy Castle API and this implementation as a dependancy, so that you don't  have to install the entire API only this installation and the parts required to
make it work.

## References

[[1](./https://www.dcs.warwick.ac.uk/~fenghao/files/J-PAKE-journal.pdf)] Hao, F., & Ryan, P. Y. A. (2010). J-PAKE: Authenticated key exchange without PKI. Computers & Security, 29(4), 475–490.

[[2](./https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)] Dang, Q. H. (2023). Recommendation for discrete logarithm-based cryptography: Elliptic curve domain parameters (NIST Special Publication 800-186). National Institute of Standards and Technology.

[[3](./https://datatracker.ietf.org/doc/html/rfc8236#page-7)] Nir, Y., & Josefsson, S. (2017). Using the Edwards-curve Digital Signature Algorithm (EdDSA) in the Internet Key Exchange Protocol Version 2 (IKEv2) (RFC 8236). Internet Engineering Task Force (IETF).

[[4](./https://github.com/bcgit/bc-java)] The Legion of the Bouncy Castle Inc. (n.d.). Bouncy Castle Java API. GitHub.











