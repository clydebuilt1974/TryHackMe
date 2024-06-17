# Introduction to Penetration Testing

### **Penetration Testing Fundamentals** <a href="#uopzd7mzvu6" id="uopzd7mzvu6"></a>

### **What is Penetration Testing?** <a href="#w8oz0qixim4j" id="w8oz0qixim4j"></a>

* Ethically-driven attempt to test security defences to protect assets and pieces of information.
* Involves using the same tools, techniques, and methodologies that an attacker would use.

### **Penetration Testing Ethics** <a href="#e4hhazb14pf0" id="e4hhazb14pf0"></a>

* Moral debate between right and wrong.
  * Where an action may be legal, it may go against an individual's belief system of right and wrong.
* A formal discussion occurs between the penetration tester and the system owner before the test begins.
  * Various tools, techniques, and systems to be tested are agreed upon.
  * This discussion forms the scope of the penetration testing agreement and will determine the course the penetration test takes.
* Companies that provide penetration testing services are held against legal frameworks and industry accreditation.
  * The National Cyber Security Centre (NCSC) has the CHECK accreditation scheme in the UK.
    * This means that only "\[CHECK] approved companies can conduct authorised penetration tests of public sector and CNI systems and networks." (NCSC).
* Penetration testers will often be faced with potentially morally questionable decisions during a penetration test.
  * Gaining access to a database and being presented with potentially sensitive data.
  * Performing a phishing attack on an employee to test an organisation's human security.
* If that action has been agreed upon during the initial stages, it is legal although ethically questionable.
* Hackers are sorted into three hats, where their ethics and motivations behind their actions determine what hat category they are placed into:

| **Category** | **Description**                                                                                                          | **Example**                                                                     |
| ------------ | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| White Hat    | These are considered "good people". They remain within the law and use their skills to benefit others.                   | A penetration tester performing an authorised engagement on a company.          |
| Grey Hat     | These use their skills to benefit others. However, they do not respect/follow the law or ethical standards at all times. | Someone taking down a scamming site.                                            |
| Black Hat    | These are criminals and often seek to damage organisations or gain some form of financial benefit at the cost of others. | Ransomware authors infect devices with malicious code and hold data for ransom. |

### **Rules of Engagement (RoE)** <a href="#x4mf00v0luvt" id="x4mf00v0luvt"></a>

* Document created at the initial stages of a penetration testing engagement.
  * Consists of three main sections that are ultimately responsible for deciding how an engagement is carried out.
* SANS institute has a great example of this document[ here](https://sansorg.egnyte.com/dl/bF4I3yCcnt/?).

| **RoE Section** | **Description**                                                                                                                                                                                                               |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Permission      | Both parties (the company wanting to test for vulnerabilities and the company conducting the pentest) will sign a document giving clear permission for the intended actions for the penetration test to be ethical and legal. |
| Test Scope      | Defines what targets or environments are being tested against. The client may only want part of their network tested and not their entire network.                                                                            |
| Rules           | Defines exactly the techniques that are permitted during the engagement. The rules may specifically state that techniques such as phishing attacks are prohibited, but MITM (Man-in-the-Middle) attacks are okay.             |

### **Penetration Testing Methodologies** <a href="#z3ovdep8ahfj" id="z3ovdep8ahfj"></a>

* The steps a tester takes during an engagement.
* Tailored to the RoE scope.
  * Having a methodology that would be used to test the security of a web application is not practical when the security of a network has to be tested.

| **Methodology Stage**                   | **Description**                                                                                                                                                                                                                                                                                                                                                                                                              |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Information Gathering                   | Often an undervalued step. Collect as much publically accessible information about a target/organisation as possible using OSINT and research. Note: This does not involve scanning any systems.                                                                                                                                                                                                                             |
| Enumeration/Scanning                    | Discover applications and services running on the systems. E.g. find a web server that may be potentially vulnerable.                                                                                                                                                                                                                                                                                                        |
| Exploitation                            | Leverage discovered vulnerabilities on a system or application. May involve the use of public exploits or exploiting application logic. Used knowledge gained from enumeration/scanning to identify and exploit vulnerabilities of any of the in scope applications.                                                                                                                                                         |
| Privilege Escalation                    | Once a system or application has been exploited (known as a foothold), attempts are made to expand access. Escalation may be horizontal or vertical. Horizontal is accessing another account of the same permission group (i.e. another user). Vertical is that of another permission group (i.e. an administrator).                                                                                                         |
| Post-exploitation                       | This has a few sub-stages: What other hosts can be targeted (pivoting), what additional information can be gathered from the host now that privileges have been escalated, covering tracks, reporting                                                                                                                                                                                                                        |
| Penetration Test Report and Clearing-up | Used to explain the results of the engagement to the client. Report ontains details regarding any security issues found and how to mitigate them. Clients will use this to understand the security issues and fix the flaws in the technology stack that was tested. Best practice is to clean up the environment that has been tested (where possible). Delete any artefacts that have been created as a result of testing. |

#### **The Open Source Security Testing Methodology Manual (OSSTMM)** <a href="#r15q5qsdgejr" id="r15q5qsdgejr"></a>

* Provides a detailed framework of testing strategies for systems, software, applications, communications and the human aspect of cybersecurity.
* Focuses primarily on how these systems communicate and so includes a methodology for:
  * Telecommunications (phones, VoIP, etc.)
  * Wired Networks
  * Wireless communications

| **Advantages**                                                                                                                            | **Disadvantages**                                                            |
| ----------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Covers various testing strategies in-depth.                                                                                               | Difficult to understand, very detailed, and tends to use unique definitions. |
| Includes testing strategies for specific targets (I.e. telecommunications and networking).                                                |                                                                              |
| Flexible depending upon the organisation's needs.                                                                                         |                                                                              |
| Meant to set a standard for systems and applications, meaning that a universal methodology can be used in a penetration testing scenario. |                                                                              |

#### **Open Web Application Security Project (OWASP)** <a href="#f0mmjk41e49s" id="f0mmjk41e49s"></a>

* Community-driven and frequently updated framework used solely to test the security of web applications and services.
* Foundation regularly writes reports stating the top ten security vulnerabilities a web application may have, the testing approach, and remediation.

| **Advantages**                                                                 | **Disadvantages**                                                                              |
| ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| Easy to pick up and understand.                                                | It may not be clear what type of vulnerability a web application has (they can often overlap). |
| Actively maintained and is frequently updated.                                 | OWASP does not make suggestions to any specific software development life cycles.              |
| Covers all stages of an engagement: from testing to reporting and remediation. | Doesn't hold any accreditation such as CHECK.                                                  |
| Specialises in web applications and services.                                  |                                                                                                |

#### **National Institute of Standards and Technology (NIST) Cybersecurity Framework** <a href="#ir4pwmwtzugk" id="ir4pwmwtzugk"></a>

* Popular framework used to improve an organisation’s cybersecurity standards and manage the risk of cyber threats.
* Provides guidelines on security controls and benchmarks for success for organisations from critical infrastructure (power plants, etc.) all through to commercial.
* Limited section on a standard guideline for the methodology a tester should take.

| **Advantages**                                                                                            | **Disadvantages**                                                                                                |
| --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Estimated to be used by 50% of American organisations by 2020.                                            | NIST has many iterations of frameworks, so it may be difficult to decide which one applies to your organisation. |
| Extremely detailed in setting standards to help organisations mitigate the threat posed by cyber threats. | Weak auditing policies, making it difficult to determine how a breach occurred.                                  |
| Very frequently updated.                                                                                  | Does not consider cloud computing, which is quickly becoming increasingly popular for organisations.             |
| NIST provides accreditation for organisations that use this framework.                                    |                                                                                                                  |
| Designed to be implemented alongside other frameworks.                                                    |                                                                                                                  |

#### **National Cyber Security Centre (NCSC) Cyber Assessment Framework (CAF)** <a href="#id-9l6nwf8prjve" id="id-9l6nwf8prjve"></a>

* Extensive framework of fourteen principles used to assess the risk of various cyber threats and an organisation's defences against these.
* Applies to organisations considered to perform "vitally important services and activities" such as critical infrastructure, banking, and the likes.
* Mainly focuses on and assesses the following topics:
  * Data security
  * System security
  * Identity and access control
  * Resiliency
  * Monitoring
  * Response and recovery planning

| **Advantages**                                                    | **Disadvantages**                                                                                                                |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Backed by a government cybersecurity agency.                      | Still new in the industry, meaning that organisations haven't had much time to make the necessary changes to be suitable for it. |
| Provides accreditation.                                           | Based on principles and ideas and isn't as direct as having rules like some other frameworks.                                    |
| Covers fourteen principles which range from security to response. |                                                                                                                                  |

### **Black box, White box, and Grey box Testing** <a href="#id-7f0h00lnz8ez" id="id-7f0h00lnz8ez"></a>

#### **Black-Box** <a href="#rbandkz02763" id="rbandkz02763"></a>

* Tester is not given any information about the inner workings of the application or service.
* Tester acts as a regular user testing the functionality and interaction of the application or piece of software.
* Testing can involve interacting with the interface, i.e. buttons, and testing to see whether the intended result is returned.
* No knowledge of programming or understanding of the programme is necessary for this type of testing.
* Black-Box testing significantly increases the amount of time spent during the information gathering and enumeration phase to understand the attack surface of the target.

#### **Grey-Box** <a href="#id-20va1s54tclm" id="id-20va1s54tclm"></a>

* Combination of black-box and white-box testing processes.
* Tester has limited knowledge of the internal components of the application or piece of software.
* Engagement will interact with the application as if it were a black-box scenario and then use the limited knowledge of the application to try and resolve issues as they are found.
* Limited knowledge given saves time, and is often chosen for extremely well-hardened attack surfaces.

#### **White-Box** <a href="#jy2twy70r0gi" id="jy2twy70r0gi"></a>

* Tester will have full knowledge of the application and its expected behaviour and is much more time consuming than black-box testing.
* Usually done by a software developer who knows programming and application logic.
* Tester will be testing the internal components of the application or piece of software and ensuring that specific functions work correctly and within a reasonable amount of time.
* Full knowledge provides a testing approach that guarantees the entire attack surface can be validated.

### **Principles of Security** <a href="#id-7v1xrl1m7pmt" id="id-7v1xrl1m7pmt"></a>

#### **Confidentiality, Integrity, Availability (CIA) Triad** <a href="#bi4ildlr8cke" id="bi4ildlr8cke"></a>

* Industry standard information security model.
* Helps determine the value of data that it applies to, and in turn, the attention it needs from the business.
* Continuous cycle as the other two CIA sections are rendered useless if one section is not met.
  * A security policy is seldom effective if it does not answer the three sections.

**Confidentiality**

* The protection of sensitive data from unauthorised access and misuse.
* Confidentiality can be applied by:
  * Vetting
    * Screening process where applicant's backgrounds are examined to establish the risk they pose to the organisation.
  * Using tight access controls or using a sensitivity classification rating system (top-secret, classified, unclassified).

**Integrity**

* Where information is kept accurate and consistent during storage, transmission, and usage unless authorised changes are made.
* Steps must be taken to ensure data cannot be altered by unauthorised users (for example, in a breach of confidentiality):
  * Access control
  * Rigorous authentication
* Help ensure that transactions are authentic and that files have not been modified or corrupted using:
  * Hash verifications.
  * Digital signatures.

**Availability**

* Information should be available when authorised users need to access it.
  * Having reliable and well-tested hardware for their information technology servers (i.e. reputable servers)
  * Having redundant technology and services in the case of failure of the primary
  * Implementing well versed security protocols to protect technology and services from attack
* Often a key benchmark for an organisation:
  * Having 99.99% uptime on their websites or systems (this is laid out in SLAs).
  * Often results in damage to an organisation's reputation and loss of finances when a system is unavailable.

### **Principles of Privileges** <a href="#id-1916xwgtszgr" id="id-1916xwgtszgr"></a>

* Vital to administrate and correctly define the various levels of access to an information technology system that users require.
* Levels of access given to individuals are determined on:
  * Individual's role/function within the organisation.
  * Sensitivity of the information being stored on the system.
* Two important concepts used to assign and manage access rights of individuals:
  * Privileged Identity Management (PIM).
    * Translates a user's role within an organisation into an access role on a system.
  * Privileged Access Management (PAM).
    * Management of the privileges that a system's access role has.
    * Encompasses enforcing security policies such as password management, auditing policies and reducing the attack surface a system faces.

#### **Principle of Least Privilege** <a href="#id-4mmmqiclyqch" id="id-4mmmqiclyqch"></a>

* Users should be given the minimum amount of privileges.
  * Only those privileges that are absolutely necessary for them to perform their duties.

### **Security Models Continued** <a href="#e7kwxytitpqr" id="e7kwxytitpqr"></a>

* Any system or piece of technology storing information is called an information system.

#### **Bell-La Padula Model (Confidentiality)** <a href="#id-34bp3rx4c5p7" id="id-34bp3rx4c5p7"></a>

* Requires well defined roles and responsibilities within the organisation's hierarchical structure.
* Works by granting access to pieces of data (objects) on a strictly need to know basis.
* Uses the rule **no write down, no read up**.
  * Subjects can create content only at or above their own security level.
    * Secret researchers can create secret or top-secret files but may not create public files; no write-down).
  * Subjects can view content only at or below their own security level.
    * Secret researchers can view public or secret files, but may not view top-secret files; no read-up).
* Popular within governmental and military.
  * Members of the organisations are presumed to have already gone through vetting.
  * Applicants who are successfully vetted are assumed to be trustworthy - which is where this model fits in.

| **Advantages**                                                                                   | **Disadvantages**                                                                                                                |
| ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| Policies in this model can be replicated to real-life organisations hierarchies (and vice versa) | Even though a user may not have access to an object, they will know about its existence so it's not confidential in that aspect. |
| Simple to implement and understand, and has been proven to be successful.                        | The model relies on a large amount of trust within the organisation.                                                             |

#### **Biba Model (Integrity)** <a href="#j16vizjybn56" id="j16vizjybn56"></a>

* Applies the rule to objects (data) and subjects (users) of **no write up, no read down**.
  * Subjects can only create content at or below their own integrity level.
    * A monk may write a prayer book that can be read by commoners, but not one to be read by a high priest; no write up.
  * Subjects can only view content at or above their own integrity level.
    * A monk may read a book written by the high priest, but may not read a pamphlet written by a lowly commoner; no read down.
* Used where integrity is more important than confidentiality.
  * In software development, developers may only have access to the code that is necessary for their job.
  * They may not need access to critical pieces of information such as databases, etc.

| **Advantages**                                                                                              | **Disadvantages**                                                                                                                                   |
| ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Simple to implement.                                                                                        | There will be many levels of access and objects. Things can be easily overlooked when applying security controls.                                   |
| Resolves the limitations of the Bell-La Padula model by addressing both confidentiality and data integrity. | Often results in delays within a business. For example, a doctor would not be able to read the notes made by a nurse in a hospital with this model. |

### **Threat Modelling** <a href="#ktg5go31cmp3" id="ktg5go31cmp3"></a>

* Process of reviewing, improving, and testing the security protocols in an organisation's information technology infrastructure and services.
* Critical stage of the process is identifying likely threats that an application or system may face, and the vulnerabilities a system or application may be vulnerable to.
* Very similar to a risk assessment.
* Requires constant review and discussion with a dedicated team:
* An effective threat model includes:
  * Threat intelligence
  * Asset identification
  * Mitigation capabilities
  * Risk assessment
* Frameworks to help with threat modelling:
  * PASTA
    * Process for Attack Simulation and Threat Analysis.
  * STRIDE was authored by two Microsoft security researchers in 1999 and is still very relevant today.

| **STRIDE Principle**   | **Description**                                                                                                                                                                                                                                            |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Spoofing               | This principle requires you to authenticate requests and users accessing a system. Spoofing involves a malicious party falsely identifying itself as another. Access keys (such as API keys) or signatures via encryption helps remediate this threat.     |
| Tampering              | By providing anti-tampering measures to a system or application, you help provide integrity to the data. Data that is accessed must be kept integral and accurate. For example, shops use seals on food products.                                          |
| Repudiation            | This principle dictates the use of services such as logging of activity for a system or application to track.                                                                                                                                              |
| Information Disclosure | Applications or services that handle information of multiple users need to be appropriately configured to only show information relevant to the owner.                                                                                                     |
| Denial of Service      | Applications and services use up system resources, these two things should have measures in place so that abuse of the application/service won't result in bringing the whole system down.                                                                 |
| Elevation of Privilege | This is the worst-case scenario for an application or service. It means that a user was able to escalate their authorisation to that of a higher level i.e. an administrator. This scenario often leads to further exploitation or information disclosure. |

### **Incident Response (IR)** <a href="#fwmx07asmh1" id="fwmx07asmh1"></a>

* A breach of security is known as an incident.
* Actions taken to resolve and remediate the threat are known as Incident Response (IR).
* Incidents are classified using a rating of urgency and impact.
  * Urgency is determined by the type of attack faced, where the impact will be determined by the affected system and what impact that has on business operations.
* An incident is responded to by a Computer Security Incident Response Team (CSIRT) who are a prearranged group of employees with technical knowledge about the systems and/or current incident.
* To successfully solve an incident, the six phases of Incident Response should take place (PICERL).

| **IR Phase**    | **Description**                                                                                                                             |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Preparation     | Are the resources and plans in place to deal with the security incident?                                                                    |
| Identification  | Has the threat and the threat actor been correctly identified to allow a response?                                                          |
| Containment     | Can the threat/security incident be contained to prevent other systems or users from being impacted?                                        |
| Eradication     | Remove the active threat.                                                                                                                   |
| Recovery        | Perform a full review of the impacted systems to return to business as usual operations.                                                    |
| Lessons Learned | What can be learnt from the incident? I.e. if it was due to a phishing email, employees should be trained better to detect phishing emails. |
