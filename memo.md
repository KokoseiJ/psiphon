server list file can be downloaded at:  
https://psiphon.ca/server_list  
(URL may vary as the address may have been blocked in some places, We can probably use the mirrors instead as they did in https://github.com/thispc/psiphon)

as the `server_list` file's format has been changed, We cannot use plain python client made by Psiphon. Which means, I have no clue about what `server_list` contains. so I will dig up to this file, and write everything that I found about that file in here.

server_list file is a big piece of dictionary. it has those keys:

* data - it is multiple strings with each pieces encoded to hex. They are separated with `\n`, so You can easily separate those pieces by using `.split("\n")`.  
as I will rewrite codes with Python 3, We cannot use `.decode("hex")` anymore. instead, we can use `bytearray.fromhex(hex_string).decode()` which will convert the hex string to the byte string and decode it to UTF-8.    
Each piece of the string has data separated with space, so you can separate it with `.split()`. It contains:
  * IP address
  * Port number(probably)
  * Something that is encoded to hex. I have no idea as it can't be just converted to UTF-8 or ASCII
  * Something that is encoded to base64. I also have no idea about it as it can't be just converted to UTF-8 or ASCII
  * another dictionary. it has those keys:
    * capabilities - List of the protocols that server supports. it contains:  
      ` `UNFRONTED-MEEK-SESSION-TICKET  
      ` `SSH  
      ` `QUIC  
      ` `OSSH  
      ` `ssh-api-requests  
      ` `UNFRONTED-MEEK-HTTPS  
      ` `FRONTED-MEEK-HTTP  
      ` `FRONTED-MEEK  
      ` `FRONTED-MEEK-QUIC  
      ` `FRONTED-MEEK-TACTICS  
      ` `UNFRONTED-MEEK  
      ` `TAPDANCE  
      ` `handshake  
      ` `VPN
    * configurationVersion
    * ipAddress - same as the one above
    * meekCookieEncryptionPublicKey
    * meekFrontingDomain
    * meekFrontingHost
    * meekObfuscatedKey
    * meekServerPorta
    * region - contains the region of the server in 2 characters
    * signature
    * sshHostKey
    * sshObfuscatedKey
    * sshObfuscatedPort
    * sshObfuscatedQUICPort
    * sshObfuscatedTapdancePort
    * sshPassword
    * sshPort
    * sshUsername
    * tacticsRequestObfuscatedKey
    * tacticsRequestPublicKey
    * webServerCertificate
    * webServerPort
    * webServerSecret
* signingPublicKeyDigest
* signature