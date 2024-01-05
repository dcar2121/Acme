# # Server Abort Error on KillSwitch Event
## _Compromises ECDSA Key Signatures_

 Leaking Bits of ECDSA Keys

- By Spacebot23

-spacebot@wearhackerone.com

- Copyright 2024 © Dwayne Hans. All Rights Reserved. 




## Table of Content

- I.	The What - Details of vulnerability in a nutshell.
- II.	The Where - Components/users affected.
- III.	The When - Exploit and PoC.
- IV.	The Why - Reason why the exploit is able to occur. 
- V.	The How - How to mitigate/fix the issue.

> 	In Loving Memory 
> 	of 
>	Ronald Leroy Jacobs


#   I. The What/ ECDSA Keys

>   	The Lindell17 Protocol which uses Paillier encryption for facilitating the generation of ECDSA signatures in the client-server, each holds a share of the ECDSA secret key and finalizes the signature. It does this by partially encrypting the client signature with the servers Paillier public key and sends the resulting cipher text to the server to be finalized into a full signature, decrypting the cipher-text and processing the data. CVE-2023-33242.

#       Cross-Script-Cache 

>   	The Client server reconstructs a string only after the data-processing step. that doesn’t verify according to the standards of ECDSA verification algorithm. The leaks in the data can be traced to a witness signature on the blockchain that’s validating the transaction with the improper ECDSA keys. But a cross-check on the recorded transactions using a bitcoin private key leak online tool reveals that the addresses made from the leaked key bits are malformed. The results indicate an encoded error message in the code of the address because the account and the transaction that occurs. Are generated using false key bits and thus creating not a real bitcoin address. This is exploited by a corrupted client which is another static web resource that we wedge between the server and cloud-flare masked as a linked financial institution content data web connection or media layer of the application that allow Client to conduct financial transactions with partner banking and crypto currency groups, this also allows for the capture the cached information remotely. The client server is configured to not allow changes or updates from attackers but this also means the server must be manually updated so use of a KillSwitch for these instances is enabled as a failsafe. However this is what’s causing the bug. It stops the malicious message request but spits back bits of the key along with the response.

#  II. The Where/ Header Cache Keys: 

	>    Recall that (standard) ECDSA signatures are calculated as follows:
	1. Sample ephemeral key k
	     (a random number between 1 and q, where q is an ECDSA constant)
	2. Calculate the public nonce r which is a function of k and public parameters
	3. Set  s = (HASH(msg) + r x ) * k^(-1) % q where msg is the message for signing and x is the ECDSA private key.
	4. Output (r,s)
	>	In the Lindell17 protocol, the secret material (i.e. the k and the x) are split between the two parties such that k = k1*k2 and x = x1+x2 and each party holds the relevant secret (say the client holds k1, x1 and the server holds k2, x2) 
	>	Furthermore, after the parties calculate r,  the client is instructed to send the server the following value encrypted under the the server’s Paillier key (the clients calculates this value by homomorphically operating on Enc(x2)) : 
	C =  Enc(HASH(msg)+r* x1 * (k1^(-1) % q)+  x2 *r * (k1^(-1) % q)) 
	>	Once the server receives C, it calculates s = k2^(-1)*dec(C) \mod q  and outputs (r,s) if it’s a valid signature.
	>	Obtaining the LSB (least significant bit)
	>	To obtain the least significant bit, the client sets k1 = 2 and maliciously sets
	C =  Enc(HASH(msg) + r* x1 * (k1^(-1) % q)+  x2 * \rho * (k1^(-1) % N)) 
	>	Where N is the public key of the encryption scheme and \rho = r if r is odd and \rho = r + q otherwise. In the end of the signature process, the validity of the signature leaks the lsb.
	>	Iterating the attack to obtain the next bits
	>	Suppose that the malicious client already knows the i-1 least significant bits (i.e. y = x2 % 2^{i-1}). To obtain the least significant bit, the client sets k1 = 2^i  (the ith power of two) and maliciously sets
	C =  Enc(HASH(msg) + r* x1 * (k1^(-1) % q)+  x2 * \rho * (k1^(-1) % N) + offset)) 
	>	Where N and \rho are as above and offset = y*rho*((k1^(-1) % q) – (k1^(-1) % N)). In the end of the signature process, the validity of the signature leaks the i-th bit.
# III. The When/ PoC - SigKey Drip
>	Steps to follow

	1.	In URL type https://coinbase.com
	2.	Click on the Sign-Up tab
	3.	Open browser webdav Inspector tool 
	4.	Under the browser devtool dashboard tab over to console 
	5.	Here is where we input some log symbol expressions any random bits using sig*
	6.	After hitting enter on the console tab over to Network
	7.	Viewing network traffic we can see the status codes of the process letting us know if its been successful the server will respond with “successful” message
	8.	Now after confirmation our message has sent us back some tid bits, tab to the Storage tab 
	9.	Under Storage tab review cookies (this is where the keys and bits are) 
	10.	View the malicious message there are two hash values here
	11.	Under the client storage we can see the server response and the malicious request including Witness signature hash that validated the invalid transactions
	12.	To verify this in the URL bar enter https://mempool.space 
	13.	Top right corner of the landing page for https://mempool.space there is a search bar where we enter in the bits (mempool finds the rest of the address surprisingly)
	14.	Taking a snippet of the revealed key bits we can piece together a grouping a lighting nodes and their related transactions clicking on a transaction to view the bitcoin address for the transaction
	15.	Using a bitcoin private key leak web tool copy the address of the transaction related to the leaked bits 
	16.	Reveals the code and line in the related address is invalid
	17.	review the attached log files included with this report 
	18.	review the video attachment (sorry it is rather long and has some idle parts, the real good stuff is toward the end portion. hey, I was performing security research in the process).

# IV. The Why / Reasoning 

>		Because information that is sent to the server which finalizes the signature or not; the information is gathered regardless because the signature does or doesn’t appear on the Blockchain; and never will but the transactions will, the client Server itself just notifies the attacker of a valid exploit in the form of tiny bits to eventually to recover after collecting 256 key signatures. This can happen rapidly in a ‘blitzed’ styled attack like here. Remembering abort events are different from time-out events. 

# V. The How/ Mitigation

>		This should never happen, the attack can be identified by the server because of the failed signature only after data-processing meaning this vulnerability may have been occurring for a period of time. Its recommended that tracking of these events and distinguishing the difference between time outs and abort events should be implemented. Upgrading the server to a non vulnerable version or implementing a enterprise aborting methods that won’t let an attacker extract additional bits after the first failed transaction (limits) on how many times the KillSwitch can be flicked. An alternative approach is to use a ZK Proof for clients last message in combination with Secure Multiparty Computation(Lindell).
 
>		“Secure Multiparty Computation | Jonas Spenger.” Jonasspenger.github.io, 1 Jan. 2024, jonasspenger.github.io/blog/secure-multiparty-computation. Accessed 2 Jan. 2024.

>		Lindell, Yehuda. “Secure Multiparty Computation (MPC).” EPrint IACR, 2020, ia.cr/2020/300. Accessed 2 Jan. 2024.

	References

>		“React Native WaaS SDK.” GitHub, 1 Jan. 2024, github.com/coinbase/waas-sdk-react-native. Accessed 2 Jan. 2024.

>		Writer, Nate NelsonContributing, et al. “Blockchain Signing Bug Cracks Open Crypto Investors’ Wallets Worldwide.” Dark Reading, 9 Aug. 2023, www.darkreading.com/vulnerabilities-threats/private-key-leaks-attackers-empty-crypto-investors-wallets.

>		Yomtov, Oren. #BHUSA @BlackHatEvents Small Leaks, Billions of Dollars: Practical Cryptographic Exploits That Undermine Leading Crypto Wallets Speakers: Nikolaos Makriyannis. 1 Jan. 2024.
`


<h1 id="toc_0">Server Abort Error on KillSwitch Event</h1>

<h2 id="toc_1"><em>Compromises ECDSA Key Signatures</em></h2>

<p>Leaking Bits of ECDSA Keys</p>

<ul>
<li>By Spacebot23</li>
</ul>

<p>-spacebot@wearhackerone.com</p>

<ul>
<li>Copyright 2024 © Dwayne Hans. All Rights Reserved. </li>
</ul>

<h2 id="toc_2">Table of Content</h2>

<ul>
<li>I.    The What - Details of vulnerability in a nutshell.</li>
<li>II.   The Where - Components/users affected.</li>
<li>III.  The When - Exploit and PoC.</li>
<li>IV.   The Why - Reason why the exploit is able to occur. </li>
<li>V.    The How - How to mitigate/fix the issue.</li>
</ul>

<blockquote>
<p>In Loving Memory 
  of 
  Ronald Leroy Jacobs</p>
</blockquote>

<h1 id="toc_3">I. The What/ ECDSA Keys</h1>

<blockquote>
<div><pre><code class="language-none">  The Lindell17 Protocol which uses Paillier encryption for facilitating the generation of ECDSA signatures in the client-server, each holds a share of the ECDSA secret key and finalizes the signature. It does this by partially encrypting the client signature with the servers Paillier public key and sends the resulting cipher text to the server to be finalized into a full signature, decrypting the cipher-text and processing the data. CVE-2023-33242.</code></pre></div>
</blockquote>

<h1 id="toc_4">Cross-Script-Cache</h1>

<blockquote>
<div><pre><code class="language-none">  The Client server reconstructs a string only after the data-processing step. that doesn’t verify according to the standards of ECDSA verification algorithm. The leaks in the data can be traced to a witness signature on the blockchain that’s validating the transaction with the improper ECDSA keys. But a cross-check on the recorded transactions using a bitcoin private key leak online tool reveals that the addresses made from the leaked key bits are malformed. The results indicate an encoded error message in the code of the address because the account and the transaction that occurs. Are generated using false key bits and thus creating not a real bitcoin address. This is exploited by a corrupted client which is another static web resource that we wedge between the server and cloud-flare masked as a linked financial institution content data web connection or media layer of the application that allow Client to conduct financial transactions with partner banking and crypto currency groups, this also allows for the capture the cached information remotely. The client server is configured to not allow changes or updates from attackers but this also means the server must be manually updated so use of a KillSwitch for these instances is enabled as a failsafe. However this is what’s causing the bug. It stops the malicious message request but spits back bits of the key along with the response.</code></pre></div>
</blockquote>

<h1 id="toc_5">II. The Where/ Header Cache Keys:</h1>

<div><pre><code class="language-none">&gt;    Recall that (standard) ECDSA signatures are calculated as follows:
1. Sample ephemeral key k
     (a random number between 1 and q, where q is an ECDSA constant)
2. Calculate the public nonce r which is a function of k and public parameters
3. Set  s = (HASH(msg) + r x ) * k^(-1) % q where msg is the message for signing and x is the ECDSA private key.
4. Output (r,s)
&gt;   In the Lindell17 protocol, the secret material (i.e. the k and the x) are split between the two parties such that k = k1*k2 and x = x1+x2 and each party holds the relevant secret (say the client holds k1, x1 and the server holds k2, x2) 
&gt;   Furthermore, after the parties calculate r,  the client is instructed to send the server the following value encrypted under the the server’s Paillier key (the clients calculates this value by homomorphically operating on Enc(x2)) : 
C =  Enc(HASH(msg)+r* x1 * (k1^(-1) % q)+  x2 *r * (k1^(-1) % q)) 
&gt;   Once the server receives C, it calculates s = k2^(-1)*dec(C) \mod q  and outputs (r,s) if it’s a valid signature.
&gt;   Obtaining the LSB (least significant bit)
&gt;   To obtain the least significant bit, the client sets k1 = 2 and maliciously sets
C =  Enc(HASH(msg) + r* x1 * (k1^(-1) % q)+  x2 * \rho * (k1^(-1) % N)) 
&gt;   Where N is the public key of the encryption scheme and \rho = r if r is odd and \rho = r + q otherwise. In the end of the signature process, the validity of the signature leaks the lsb.
&gt;   Iterating the attack to obtain the next bits
&gt;   Suppose that the malicious client already knows the i-1 least significant bits (i.e. y = x2 % 2^{i-1}). To obtain the least significant bit, the client sets k1 = 2^i  (the ith power of two) and maliciously sets
C =  Enc(HASH(msg) + r* x1 * (k1^(-1) % q)+  x2 * \rho * (k1^(-1) % N) + offset)) 
&gt;   Where N and \rho are as above and offset = y*rho*((k1^(-1) % q) – (k1^(-1) % N)). In the end of the signature process, the validity of the signature leaks the i-th bit.</code></pre></div>

<h1 id="toc_6">III. The When/ PoC - SigKey Drip</h1>

<blockquote>
<p>Steps to follow</p>
</blockquote>

<div><pre><code class="language-none">1.  In URL type https://coinbase.com
2.  Click on the Sign-Up tab
3.  Open browser webdav Inspector tool 
4.  Under the browser devtool dashboard tab over to console 
5.  Here is where we input some log symbol expressions any random bits using sig*
6.  After hitting enter on the console tab over to Network
7.  Viewing network traffic we can see the status codes of the process letting us know if its been successful the server will respond with “successful” message
8.  Now after confirmation our message has sent us back some tid bits, tab to the Storage tab 
9.  Under Storage tab review cookies (this is where the keys and bits are) 
10. View the malicious message there are two hash values here
11. Under the client storage we can see the server response and the malicious request including Witness signature hash that validated the invalid transactions
12. To verify this in the URL bar enter https://mempool.space 
13. Top right corner of the landing page for https://mempool.space there is a search bar where we enter in the bits (mempool finds the rest of the address surprisingly)
14. Taking a snippet of the revealed key bits we can piece together a grouping a lighting nodes and their related transactions clicking on a transaction to view the bitcoin address for the transaction
15. Using a bitcoin private key leak web tool copy the address of the transaction related to the leaked bits 
16. Reveals the code and line in the related address is invalid
17. review the attached log files included with this report 
18. review the video attachment (sorry it is rather long and has some idle parts, the real good stuff is toward the end portion. hey, I was performing security research in the process).</code></pre></div>

<h1 id="toc_7">IV. The Why / Reasoning</h1>

<blockquote>
<div><pre><code class="language-none">  Because information that is sent to the server which finalizes the signature or not; the information is gathered regardless because the signature does or doesn’t appear on the Blockchain; and never will but the transactions will, the client Server itself just notifies the attacker of a valid exploit in the form of tiny bits to eventually to recover after collecting 256 key signatures. This can happen rapidly in a ‘blitzed’ styled attack like here. Remembering abort events are different from time-out events. </code></pre></div>
</blockquote>

<h1 id="toc_8">V. The How/ Mitigation</h1>

<blockquote>
<div><pre><code class="language-none">  This should never happen, the attack can be identified by the server because of the failed signature only after data-processing meaning this vulnerability may have been occurring for a period of time. Its recommended that tracking of these events and distinguishing the difference between time outs and abort events should be implemented. Upgrading the server to a non vulnerable version or implementing a enterprise aborting methods that won’t let an attacker extract additional bits after the first failed transaction (limits) on how many times the KillSwitch can be flicked. An alternative approach is to use a ZK Proof for clients last message in combination with Secure Multiparty Computation(Lindell).

  “Secure Multiparty Computation | Jonas Spenger.” Jonasspenger.github.io, 1 Jan. 2024, jonasspenger.github.io/blog/secure-multiparty-computation. Accessed 2 Jan. 2024.

  Lindell, Yehuda. “Secure Multiparty Computation (MPC).” EPrint IACR, 2020, ia.cr/2020/300. Accessed 2 Jan. 2024.</code></pre></div>
</blockquote>

<div><pre><code class="language-none">References</code></pre></div>

<blockquote>
<div><pre><code class="language-none">  “React Native WaaS SDK.” GitHub, 1 Jan. 2024, github.com/coinbase/waas-sdk-react-native. Accessed 2 Jan. 2024.

  Writer, Nate NelsonContributing, et al. “Blockchain Signing Bug Cracks Open Crypto Investors’ Wallets Worldwide.” Dark Reading, 9 Aug. 2023, www.darkreading.com/vulnerabilities-threats/private-key-leaks-attackers-empty-crypto-investors-wallets.

  Yomtov, Oren. #BHUSA @BlackHatEvents Small Leaks, Billions of Dollars: Practical Cryptographic Exploits That Undermine Leading Crypto Wallets Speakers: Nikolaos Makriyannis. 1 Jan. 2024.</code></pre></div>

<p>`</p>
</blockquote>
