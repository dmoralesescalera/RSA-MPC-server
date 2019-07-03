# Introduction
This is a MultyParty Computation System Prototipe wich provides distributed RSA key management (key pair creation and signing operations, but can be extended to decryption too). 
It is based on Atle Mauland work, which integrate the distributed RSA protocol into VIFF code (VIFF is a Python framework for MPC).

-[Protocolo para RSA distribuido](https://www.researchgate.net/publication/266524261_Realizing_Distributed_RSA_using_Secure_Multiparty_Computations)

-[Plataforma VIFF](http://viff.dk/)

The objective of this contribution is to provide a test environment, wich can be easyly deployed, emulating a cloud server architecture wich provides a service for clients. In this way, a client entity (one user or domain), can take advantage of the key management service offered via an orchestrator element. The key management service provides a virtual Hardware Security Module, thanks to MPC properties.

## Architecture

(https://raw.githubusercontent.com/dmoralesescalera/RSA-MPC-server/pics/Arquitectura-Arquitectura general.jpeg)
