# Introduction
This is a MultyParty Computation System Prototipe wich provides distributed RSA key management (key pair creation and signing operations, but can be extended to decryption too). 
It is based on Atle Mauland work, which integrate the distributed RSA protocol into VIFF code (VIFF is a Python framework for MPC).

-[Distributed RSA protocol](https://www.researchgate.net/publication/266524261_Realizing_Distributed_RSA_using_Secure_Multiparty_Computations)

-[VIFF - Virtual Ideal Functionality Framework](http://viff.dk/)

The objective of this contribution is to provide a test environment, wich can be easyly deployed, emulating a cloud server architecture wich provides a service for clients. In this way, a client entity (one user or domain), can take advantage of the key management service offered via an orchestrator element. The key management service provides a virtual Hardware Security Module, thanks to MPC properties.

## Architecture

-[System Architecture Picture](https://github.com/dmoralesescalera/RSA-MPC-server/blob/master/pics/architecture.jpg)

The system architecure is built over three tiers. On top, there are the servers, with a flat design, meaning they do not develop the logic that make the system works. This is the orchestrator function, on second tier, wich translate client requests and coordinates the servers.
The servers use the information provided by orchestrator to start a MPC operation. Clients are thaught in abstract way, meaning they can perform any desired operation.

A client example has be developed, for certificate signing operations with the certbuilder Python library:

-[Certbuilder client with MPC](https://github.com/dmoralesescalera/certbuilder)

## Working Instructions
