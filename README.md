**TL;DR**

* Python tool that generates an Xmind map with all the information gathered and any evidence of possible vulnerabilities identified via static analysis.
* The map itself is an Android Application Pentesting Methodology component, which assists Pentesters to cover all important areas during an assessment. This was the main goal driving the tool development.
* The tool also allows to add custom checks in a simple way, to confirm the existence of those patterns in the dalvik bytecode instructions.

![Sample Analysys](https://github.com/integrity-sa/droidstatx/raw/master/sample.png "Sample Analysys")

**Installation (Tested on Kali 2017)**

You have two options. Use Docker with the provided docker file or use the following instructions for manual setup:

***Pre-requisites***

* pip (apt-get install python-pip)
* Java JRE (Probably already installed but if not, apt-get install default-jre)

***Instructions***

* git clone https://github.com/integrity-sa/droidstatx.git
* cd droidstatx
* python install.py
  * The setup will download the latest jar version of apktool and pip install androguard and xmind-sdk-python. 

**Usage**

* python droidstatx.py --apk <apk>

**Config File (droidstatx.config)**

***[Settings]*** - General Settings
* xmindTopicStructure: Set the xmind topic structure for the file.
* topicFoldAt: Number of maximum subtopics at which the parent topic will be folded by default.
* fileExclusions: Extensions and Paths configured to be excluded in File info gathering.
* folderExclusions: Folders to be excluded during the static analysis proccesss.
* maxSubTopics: Maximum of subtopics on each topic. Currently only used for the Files topic.

***[CustomChecks]*** - Area to configure custom checks
* Custom checks are defined one per line, as per the following format:

  \<nameToAppearInXmindTopic\> = \<regex pattern\>

**Methodology**

As stated above, this was the tool development's main driving goal. The Xmind map Methodology topic is structured following the OWASP Mobile TOP 10 2016 categories

Each category has topics that you will need to cover in the format of a checklist, to guarantee and highlight coverage.
Each topic has a URL to the respective chapter in the OWASP The Mobile Security Testing Guide (MSTG) explaining the vulnerability and how to confirm its existence.
I collaborated a little bit on the OWASP MSTG project and have to give a big shout out to Bernhard and Sven for creating the project and bringing a lot of people together to develop it. 

The tool will automatically fill some of the topics with evidences based on the analysis, to help confirm if it is a false or a true positive.

Each time the tool runs against a package, if the xmind map already exists,a new tab will be created on the workbook. This way it’s possible to keep a history file of every new version tested and compare it against previous runs.

**Information Returned**
* Package Properties
  * Package Name
  * Version Name
  * Version Code
  * File SHA256
  * Minimum SDK Version
  * Target SDK Version
  * Technology/Framework fingerprinting
      * Outsystems
      * Cordova
          - Used Plugins 
      * Xamarin
          - Determine if DLL's are bundled (Automatic extraction of DLL's to output_dlls folder)
  * Determine if the backup option is enabled
  * Determine if the package has multiple dex files
  * Check for presence of secret codes
* Permissions
* Exported Components with respective intent-filters and permissions
* Package Files (some extensions are filtered by default;configurable.)
* Object Usage
  * WebViews loadUrl
  * Cryptographic Functions
  * Custom Checks (configurable.)
* Components Security Related Evidences Checks
  * Fragment Injection
  * Lack of FLAG_SECURE or android:excludeFromRecents in activities
  * Path Traversal and SQL Injection in exported ContentProviders 
* Package Security Related Evidences Checks
  * Determine if the application is debuggable 
* Webiews Security Related Evidences Checks
  * Usage of AddJavascriptInterface (Based on the minimum SDK version, the evidence will indicate RCE possibility or not)
  * Usage of Javascript Enabled
  * Usage of fileAccess Enabled
  * Usage of UniversalAccessFromFileURLs Enabled
* TLS Security Related Evidences Checks
  * Vulnerable TrustManagers
  * Vulnerable HostnameVerifiers
  * Webviews Vulnerable onReceivedSslError Method
  * Direct usage of Socket without HostnameVerifier
  * Determine the usage of NetworkSecurityConfig file
    * Check Clear Text Allow
    * Check if Pinning is Enabled
    * Check Pinning Expiration Date
    * Check if User CA's are trusted
  * Determine the usage of Certificate Pinning (Custom and okHTTP)
* Cryptography Security Related Evidences Checks
  * Usage of AES with ECB
  * Usage of DES or 3DES
  * Determine the usage of Android Keystore

**Under the Hood**

Androguard toolkit from Anthony Desnos is being used to gather all the package info (properties,components,files,etc).

For the Xmind map generation, XMind SDK for python from Xmind is being used, which unfortunately stopped receiving updates 4 years ago. A project fork was required to add some features like the support for the topic structure. A pull request was made with these changes to their repo. If the request is merged, the project will start using their repo instead.

The static code analysis is being done by using apktool from Ryszard Wiśniewski and Connor Tumbleson to disassemble the Dalvik bytecode and then use grep and sed for pattern checking.

**A Long Time Ago in a Galaxy Far, Far Away...**

The development of Droidstat started mid 2015 and it was presented in July in Bsides Lisbon 2015 (Slides). Life got in the way and with the typical fear of releasing ugly code online, the tool was kept private at the time.

Droidstat aims to be a static/dynamic analysis framework, which does more than just flag issues (there are already several ones which do that, like Androbugs or MobSF), it allows to create a methodology and a workflow to achieve consistency.

Right now, this standalone module is being released as a quick win, but sometime during this year, it will be released the first web interfaced version of the framework.

**Here Be Dragons**

Based on the work started on 2015, and since I wanted to learn and improve my understanding of Dalvik Bytecode, I created all the static checks from scratch, following my own thinking/approach. Other tools’ approaches will differ.

That being said, I've tested the tool against the top 30 applications in the Play Store, around 60 other applications, including several vulnerable applications created for the effect, and manually performed the review on all of them to try and guarantee the tool’s accuracy and completeness but there may exist scenarios where the tool will not behave correctly; if you find any bugs, or incorrect or missing information,please create an Issue on the project.

**References**
* [Hacking Androids for fun and Profit - Riley Hassel](http://conference.hitb.org/hitbsecconf2011kul/materials/D1T1%20-*%20Riley%20Hassell%20-%20Exploiting%20Androids%20for%20Fun%20and%20Profit.pdf)
* [Android: From Reversing to Decompilation - Anthony Desnos, Geoffroy Gueguen](https://media.blackhat.com/bh-ad-11/Desnos/bh-ad-11-DesnosGueguen-Andriod-Reversing_to_Decompilation_Slides.pdf)
* [Automated Analysis and Deobfuscation of Android Apps & Malware - Jurriaan Bremer](http://jbremer.org/wp-posts/athcon.pdf)
* [Android Secure Coding - Hiroshi Kumagai & Masaki Kubo](https://www.jpcert.or.jp/present/2014/20140910android-sc.pdf)
* Android Hacker's Handbook (Book)
* Android Security Internals (Book)
* The Mobile Application Hacker's Handbook (Book)

