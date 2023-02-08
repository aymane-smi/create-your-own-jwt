# create your own jwt library for you application from scratch

## what is JWT

`JWT` is a proposed Internet standard for creating data with optional signature and/or optional encryption whose payload holds JSON that asserts some number of claims. The tokens are signed either using a private secret or a public/private key.

## explination of the source code

| function | details|
| ---------|--------|
| sign()   | this method accept 2 parameters, a payload that contain your json and crypting algorithm in our case we going to use only `SHA256` and `SHA512`.     |
|decode()   | accept only one parameter which is the token then decode and return the payload in his json format.
| verify() | method that accept to parameters the first one for the token and the second one for the crypting algorithms(`SHA256` or `sha512`), this method return the payload only if the token is valid.|