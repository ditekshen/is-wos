## Information Stealers Wall of Sheep Analysis

## Table of Contents
- [Observations](#observerations)
- [Correlations](#correlations)
    - [The 'ROBO' Gang (Formerly: Correlation 'Fire Them')](#the-robo-gang-formerly-correlation-fire-them)
    - [Correlation 'Repetition Makes Perfect'](#correlation-repetition-makes-perfect)
    - [Correlation 'Impersonation'](#correlation-impersonation)
    - [Correlation 'Steering Towards Arid Yandex Pastures'](#correlation-steering-towards-arid-yandex-pastures)
    - [Correlation 'Gmail Abuse'](#correlation-gmail-abuse)
    - [Correlation 'The Shifters'](#correlation-the-shifters)
    - [Correlation 'Encrypt or not to Encrypt'](#correlation-encrypt-or-not-to-encrypt)
    - [Correlation 'Why even bother?'](#correlation-why-even-bother)
    - [Correlation 'FTP vs. SMTP'](#correlation-ftp-vs-smtp)
    - [Correlation 'I Speak FTP Only'](#correlation-i-speak-ftp-only)
- [Information Stealers HTTP Panels](#information-stealers-http-panels)

## Observations

### 2020-06-03

- The 'ROBO' operators heavily utilized __MassLogger__ with over 40 samples, making it a few samples away from exceeding __HawkEye__ samples.
- The 'ROBO' operators enabled HTTP POST to __MassLogger__ /panel/upload.php, along with SMTPS exfiltration.

### 2020-05-17

- A spike in __M00nD3v__ (8 unique samples) and __MassLogger__ (15 unique samples) usage is observed due to considerable adoption by the 'ROBO' operators. The same accounts and passwords are used interchangeably between the two malware families, and changed passwords for some existing accounts. The operators also attempted to influence analysis and deflect attribution by using Chinese names or the mention of the word "china" in their accounts. Probably not a smart tactic.

### 2020-05-13

- The number of unique samples and relatively recent __MassLogger__ exceeded the number of __Phoenix__ samples. This is due to large-scale adoption of MassLogger by the operators under the 'ROBO' correlation, contributing 26 unique samples so far. With this observation, the operators are known to use AgentTesla, HawkEye, M00nD3v, and Masslogger, potentially concurrently.

### 2020-05-11

- Between 2020-05-11 and 2020-05-13, the operators under the 'ROBO' correlation started utilizing __MassLogger__ keylogger, exfiltration account and password correlation; the same accounts and passwords are observed being used with AgentTesla, HawkEye, and M00nD3v samples.

### 2020-05-7

- Between 2020-05-03 and 2020-05-07, the operator under the 'Impersonation' correlation started utilizing __MassLogger__ keylogger. 
- Between 2020-05-05 and 2020-05-08, the operator of the "__tashpita__" domain under the 'I Speak FTP Only' correlation started utilizing __MassLogger__ keylogger. The opertor in this case configured the sample for both FTP and SMTP exfiltration.

### 2020-05-01

A new keylogger known as __M00nD3v__ is introduced. This keylogger is potentially used by the same operators under the 'ROBO' correlation, based on on password analysis and correlation.

- Between 2020-04-29 and 2020-05-02, the operators under the 'ROBO' correlation starting utilizing __M00nD3v__ keylogger.

### General Observations

- Most abused network for exfiltration is PublicDomainRegistry PDR (AS394695). HawkEye samples/operators seem to favor NameCheap, Inc. (AS22612), which happens to be the second most abused network. Yandex LLC (AS13238) comes in third place.
- AgentTesla is the most used information stealer.
- Operators utilize samples from different information stealer families.
- Some operators shift to utilize new keyloggers such as __M00nD3v__ and __MassLogger__ as highlighted under the 'The Shifters' correlation.
- Actors abuse Gmail for SMTP exfiltration, which provides interesting correlations as demonestrated in the "Gmail Abuse" correlation.
- Operators share passwords across multiple samples, families, and exfiltration accounts.
- Although plaintext SMTP was used for the majority of exfiltration across the families, almost all families used SMTPS for encrypted exfiltration.
- SMTP, FTP, and HTTP exfiltration was observed by some families, separately. For example, AgentTesla was observed to use SMTP, FTP and HTTP, and HawkEye was observed to use SMTP and FTP.
- Some samples employed timestopming on the compilation timestamp, some of which were static.
- Some samples used a non-standard SMTP destination port 26 as a means of evasion.
- None of the binaries was signed.

[Top](#information-stealers-wall-of-sheep-analysis)

## The 'ROBO' Gang (Formerly: Correlation 'Fire Them')

The 'ROBO' name is derived from the name the operators use to refer to themselves; the "Robot Pirates". This reference is observed in their malware distribution domains, and the webshells they employ to manage their hosted malware directories. The 'ROBO' operators maintain a very active and rapid malicious profile.

```html
<title>We are the robot pirates.We have robot functions.But we have pirate duties.</title>
```

### Profile:

- CVE-2017-11882 malspam, mostly in the form of small .RTF documents prepared to download the 2nd-stage payload.
- Direct malspam attachements in the form of .ZIP and .RAR archives.
- Exclusively exfiltrate stolen data to ```mail.privateemail.com``` on ```198.54.122.60``` at AS22612 Namecheap, Inc (NAMECHEAP-NET).
- Access to a wide range of commodity infromation stealers.
- Occasionally, the operators timestomp compilation times to the future.
- Setup of open directories to host 2nd-stage payloads. Open directories differ in their setup as follows:
  - One open directory hosting either a signle information stealer family or a combination of two families. For example, most recently, MassLogger and M00nD3v are hosted on the same directory.
  - Maltiple sub-directories under the same parent directory. Each sub-directory contains a single malware executable.
  - Open directories often include the WSO webshell (examples: bo.php, docb.php, note.php) to allow the operators manage their payloads.
  - More recently, an upload form (example: bo.php) was added along with a log file capturing associated errors (example: error_log).

### Confirmed Information Stealer Families:

- AgentTesla.
- HawkEye.
- MassLogger.
- M00nD3v.

### Potential Information Stealer Families:

- NanoCore.
- Formbook.

### Significant Activities Timelines:

- Before 2020-04-29, the operators utilized HawkEye and AgentTesla. HawkEye was the predominant stealer in use.
- Between 2020-04-29 and 2020-05-02, the operators started utilizing the M00nD3v stealer.
- Between 2020-05-11 and 2020-05-13, the operators started utilizing the MassLogger stealer.
- Between 2020-05-13 and 2020-06-03, the operators massively adopted MassLogger and M00nD3v for their operations.
- Bweteen 2020-06-01 and 2020-06-03, the operators enabled HTTP-based exfiltration in MassLogger for a specific batch of samples (Jakartta).

### Associated Open Directories:
```
http://duluran.com/site/images/screen
http://scoalalunadesus.eu/revista/pdf/doxu
http://funnelwebdesigns.com/boos
http://deltacontrol.net.pk/wp-admin/docsx
http://searisevet.com/asdmins
http://transgear.in/ssc/fada
http://ng.idiawarriorqueen.com/css/
http://yatesassociates.co.za/documentato/
http://yatesassociates.co.za/panel/login/index.php (MassLogger HTTP Panel)
http://microtechnology.hk/wapdast/
```

### Statistics:

- Total Unique Samples: 232
- MassLogger: 140
- HawkEye: 58
- M00nD3v: 19
- AgentTesla: 15

### Analysis

The below table displays the accounts and associated passwords across multiple malware families. Accounts with more than one passwords demonstrates that the operators changed the password of the account. This means that older samples with a previous password may no longer exfiltrate stolen data. This indicates the rapid nature of these operators.

| Account                                      | Total Count | Family                                            | Count                | Passwords                                                                            |
|----------------------------------------------|-------------|---------------------------------------------------|----------------------|--------------------------------------------------------------------------------------|
| ```billions@cairoways.me```                  | 23          | MassLogger</br>M00nD3v</br>AgentTesla</br>HawkEye | 16</br>4</br>2</br>1 | ```Whyworry90#```</br>```MOREMONEY123```                                             |
| ```mpa@cairoways.me```                       | 6           | MassLogger                                        | 5                    | ```BLESSEDyear20```</br>```LifeDrama@#```</br>```NewBlessings```                     |
| ```uz@cairoways.me```                        | 7           | MassLogger                                        | 7                    | ```pAsSword@#1```</br>```09012345@```                                                |
| ```admin@cairoways.me```                     | 4           | MassLogger</br>M00nD3v</br>AgentTesla             | 2</br>1</br>1        | ```requestShow@```                                                                   |
| ```sales001@cairoways.me```                  | 3           | MassLogger</br>M00nD3v                            | 2</br>1              | ```whyworry01#```                                                                    |
| ```info@abuodehbros.co```                    | 6           | MassLogger</br>HawkEye                            | 5</br>1              | ```@willsmith1.,```                                                                  |
| ```sales@abuodehbros.co```                   | 4           | MassLogger</br>M00nD3v                            | 3</br>1              | ```1234567890```                                                                     |
| ```finance@supreme-sg.icu```                 | 10          | MassLogger</br>M00nD3v</br>AgentTesla             | 7</br>2</br>1        | ```BIGGOD1234```</br>```biggod1234@```                                               |
| ```binu@metalfabme.icu```                    | 10          | MassLogger                                        | 10                   | ```@Mexico1.,```</br>```@Mexico3,.```</br>```@Brazil20,,```                          |
| ```bob@metalfabme.icu```                     | 7           | MassLogger</br>M00nD3v                            | 6</br>1              | ```@Mexico1.,```                                                                     |
| ```wiz@metalfabme.icu```                     | 5           | MassLogger</br>M00nD3v                            | 4</br>1              | ```Whyworry#@```                                                                     |
| ```huangjianping@chinacables.icu```          | 5           | MassLogger</br>M00nD3v                            | 3</br>2              | ```whyworry10902020```</br>```whyworry1090#```                                       |
| ```charif.yassin@cronimet.me```              | 5           | HawkEye</br>AgentTesla                            | 4</br>1              | ```@mile31.,```                                                                      |
| ```produccion@servalec-com.me```             | 5           | HawkEye                                           | 5                    | ```@bongo1.,```</br>```biggod1234```</br>```BIGgod1234```                            |
| ```success@poylone.com```                    | 5           | HawkEye                                           | 5                    | ```@qwerty12345```                                                                   |
| ```lchandra@bazciproduct.com```              | 8           | MassLogger                                        | 8                    | ```Mariodavid89```</br>```whywori#@#```                                              |
| ```info23@huatengaccessfloor.icu```          | 5           | MassLogger                                        | 5                    | ```1234567890```</br>```1234567891```                                                |
| ```imports@eastendfood-uk.icu```             | 5           | HawkEye                                           | 5                    | ```GGASDXZAFCVB65```</br>```GodGrace6665555```                                       |
| ```admin@bazciproduct.com```                 | 5           | MassLogger                                        | 5                    | ```@123098#```                                                                       |
| ```ampall@ampail.com```                      | 6           | MassLogger</br>M00nD3v                            | 5</br>1              | ```123098322@#```                                                                    |
| ```wetground@poylone.com```                  | 4           | HawkEye                                           | 4                    | ```@qwerty12345```                                                                   |
| ```gavin@jandregon.com```                    | 4           | HawkEye</br>AgentTesla                            | 3</br>1              | ```WHYworry??#```                                                                    |
| ```docs@hdtrans.me```                        | 6           | MassLogger</br>M00nD3v                            | 5</br>1              | ```@A120741#```                                                                      |
| ```rfy_sales806@dgrrfy.com```                | 4           | MassLogger                                        | 4                    | ```biggod1234@```                                                                    |
| ```inkyu@dubhe-kr.icu```                     | 5           | MassLogger</br>M00nD3v                            | 4</br>1              | ```SometimesINLIFE@```                                                               |
| ```m.gorecka@criiteo.com```                  | 5           | MassLogger</br>M00nD3v                            | 4</br>1              | ```efforting@```                                                                     |
| ```gestionesolleciti@pec-warrantgroup.icu``` | 5           | MassLogger                                        | 5                    | ```NoisyGeneration#@```                                                              |
| ```panos@skepsis-sg.icu```                   | 3           | HawkEye                                           | 3                    | ```breakinglimit@```</br>```@Bongo1.,```                                             |
| ```ikuku@poylone.com```                      | 3           | AgentTesla</br>HawkEye                            | 3</br>1              | ```BLESSEDchild@```</br>```GODhelpme@#```</br>```GodAbegOo#```</br>```HELPmeLORD@``` |
| ```yosra.gamal@csatolin.com```               | 3           | HawkEye</br>AgentTesla                            | 2</br>1              | ```HELPmeLORD@```</br>```@Mexico1.,```                                               |
| ```justin@allaceautoparts.me```              | 5           | MassLogger                                        | 5                    | ```HelpMELord@#```</br>```NewBlessings@```</br>```GODABEG@```                        |
| ```dcaicedo@igihm.icu```                     | 3           | AgentTesla</br>HawkEye                            | 2</br>1              | ```MOREMONEY123```</br>```STAYSAFE123```                                             |
| ```imports@techin.icu```                     | 5           | MassLogger</br>M00nD3v                            | 4</br>1              | ```biggod12345```</br>```1234567890```</br>```MoreGrace@#```                         |
| ```jplunkett@bellfilght.com```               | 3           | AgentTesla</br>HawkEye                            | 2</br>1              | ```biggod12345@```                                                                   |
| ```xu@weifeng-fulton.com```                  | 3           | HawkEye                                           | 3                    | ```@bongo1.,```                                                                      |
| ```jasmine@cinco.icu```                      | 3           | HawkEye                                           | 3                    | ```Biggod1234```</br>```biggod1234```                                                |
| ```s.ewaldt@otv-international.me```          | 2           | MassLogger</br>M00nD3v                            | 1</br>1              | ```1234567890```                                                                     |
| ```jamit@cairoways.icu```                    | 2           | HawkEye                                           | 2                    | ```breakinglimit100%```                                                              |
| ```yg@cairoways.icu```                       | 1           | HawkEye                                           | 2                    | ```ygsus2020```                                                                      |
| ```stephanie.giet@technsiem.com```           | 2           | HawkEye</br>AgentTesla                            | 1</br>1              | ```Whyworry90#```                                                                    |
| ```service@ptocs.xyz```                      | 2           | HawkEye                                           | 2                    | ```bigGod1234@```                                                                    |
| ```sales@americantrevalerinc.com```          | 3           | MassLogger                                        | 3                    | ```1q2w3e4r5t```                                                                     |
| ```info@americantrevalerinc.com```           | 4           | MassLogger                                        | 4                    | ```1q2w3e4r5t```                                                                     |
| ```accounting@americantrevalerinc.com```     | 2           | MassLogger                                        | 2                    | ```1q2w3e4r5t```                                                                     |
| ```works@americantrevalerinc.com```          | 2           | MassLogger                                        | 2                    | ```1q2w3e4r```                                                                       |
| ```supplier@americantrevalerinc.com```       | 2           | MassLogger                                        | 2                    | ```1q2w3e4r```                                                                       |
| ```doreen.muhebwa@microhaem-ug.co```         | 1           | HawkEye                                           | 1                    | ```1234567890```                                                                     |
| ```accounts@friendships-ke.icu```            | 1           | HawkEye                                           | 1                    | ```INGODWETRUST```                                                                   |
| ```info@friendships-ke.icu```                | 1           | HawkEye                                           | 1                    | ```@bongo1.,```                                                                      |
| ```ahmadi@gheytarencarpet.com```             | 1           | HawkEye                                           | 1                    | ```Focus$Pray```                                                                     |
| ```parisa@abarsiava.com```                   | 1           | HawkEye                                           | 1                    | ```@Mexico1.,```                                                                     |
| ```sav@emeco.icu```                          | 1           | HawkEye                                           | 1                    | ```GodsPlan@#```                                                                     |
| ```raphael@gitggn.com```                     | 1           | HawkEye                                           | 1                    | ```@mexico1.,```                                                                     |
| ```v.clemens@slee-de.me```                   | 1           | HawkEye                                           | 1                    | ```@mexicod1.,```                                                                    |
| ```tina.meng@wingsun-chine.com```            | 1           | MassLogger                                        | 1                    | ```@Mexico1.,```                                                                     |
| ```candolkar.p@tecnicasreunidas-es.co```     | 1           | MassLogger                                        | 1                    | ```@Mexico1.,```                                                                     |
| ```sale@somakinya.com```                     | 1           | HawkEye                                           | 1                    | ```Wenenighty.,```                                                                   |
| ```valentina.marangon@gruppodigitouch.me```  | 1           | MassLogger                                        | 1                    | ```NEWways@```                                                                       |
| ```contact@assocham.icu```                   | 1           | HawkEye                                           | 1                    | ```GODSGRACE123```                                                                   |

An interesting systematic anomaly associted with these operators is a set of 18 unique samples, which can be divided into two groups based on the domain name used in the accounts.

| Account                                      | Count | Family     | Passwords                                                                            |
|----------------------------------------------|-------|------------|--------------------------------------------------------------------------------------|
| ```obuman@akonuchenwam.org```</br>```obino@akonuchenwam.org```</br>```nednwoko@akonuchenwam.org```</br>```mobite@akonuchenwam.org```</br>```martinze@akonuchenwam.org```</br>```manman@akonuchenwam.org```</br>```dogman@akonuchenwam.org```</br>```abu@akonuchenwam.org```</br>```aboyo@akonuchenwam.org``` | 1</br>1</br>1</br>1</br>1</br>1</br>1</br>1</br>1     | MassLogger | ```(SLYNY(3```</br>```)^nveCU9```</br>```H*XyvM)5```</br>```HaLzYAY8```</br>```QMvStW^7```</br>```dho)YOW7```</br>```fySnrmX9```</br>```i^*Moaf0```</br>```mMtRZHe4``` |
| ```smithyjazz@jakartta.xyz```</br>```obuzsolidcash@jakartta.xyz```</br>```obielvosky@jakartta.xyz```</br>```nednwokoro@jakartta.xyz```</br>```mobiteeuro@jakartta.xyz```</br>```martinez@jakartta.xyz```</br>```manofficialbless@jakartta.xyz```</br>```dogdollars@jakartta.xyz```</br>```aboyo@jakartta.x``` | 1</br>1</br>1</br>1</br>1</br>1</br>1</br>1</br>1 | MassLogger | ```anosky90```</br>```bobby654```</br>```chuksweeda345```</br>```dandollars45```</br>```ginger31```</br>```moneyguy76```</br>```nwaotu65```</br>```odenigbo090```</br>```winnerq1``` |

Hashes

```
001b14d21f1f99aae9ae6b365482be3cd75568e33a8af6aba36d148129ac19dc
0088497f4ffbdf48b4b5401503a8960b7bf493e3e0ac574c6ade1695520300f9
02bb0ff54a31436e39c168c4e55237aeb972098a8da8e83eb1cbc99796a60394
033cccd5c1d6affd3269077550ba942b144fe64092c83e8c1a70ab06468206a7
03968a3a5a7a880feefca31686fcfbed445080a0c06eda2b6d623757179b782c
03beb3f3181673b3c770ef7a42fa96c13c3c1b554e77885b0c2817fcbab01299
040e25260744568a97c4fab438098f03718eaee0604a22dfe5138b73578815e0
05e415b37da05805bd1057a69697f89e1766eb91dd632bf672125f37563c49d0
069f0dc72189e7faf5278aabd6ba9f53c386023f9d7d8ab863896e43f6a4e456
0722cedd5a2e4a5a4c94ac988f14800a6a83a8c7147f7ef52b47ae86571384e2
07236ee497bab6187ef9e5ea42f6a184a9bb32030b50d88f251a449b03890305
07426d1fa6cc07107277cedeb0ed843fba44a79bf71fd228b3e74b5aaa5b9e4b
083c70afde1be48426ebcf28eacfa0cd47f96130790b79f5a367ae6b00eab142
093021d7dfcac2a0fb28007f98413ab66df6efd8b942571dff1198a5587c8807
0981eed2da1ddb0d93b002274bb01aa64a44a7af785c36b4bf66f21f7ba882b3
0a375c52851b79c5d3be0d18025940bee5f68501c8e18334264f116775e57fa7
0a7104481d9a86895362b28a49420c90427054217fd82ba9a5ebbb2a086e61a2
0ac30990fdf9e06367b60690e98803de01f668f8bc6b76c673a9295acb435d16
0c2cc0b045d670852f628dad967894fa549de4a3dca0fd13ac5e9307a5b262a6
0ea5d6d7d7e520a61a396c77d166dd1cb34cde965d3788430c3484a616381c74
0f22bd1e202b2fa87adfca75ca61405ac232863a75ab7b5a71a69c3b7c22e7b1
0f589bd3c4bfdf1301a52c6b4b9f9202ab61131bb7230f4e91767b28894005b2
0f7facae07fd7efc8eb9a2b6916eb8d912fe48d3a74a9629d110856df8144a65
0f831f1d2ec54e999f14a8ef2d7f38c9fdc69670f67e55c71d9f0b7bd808fc74
0ffa7ac2091ab004e6755e1e66539633b6a628e90094d80357895df0e6092f9c
0ffe5ec768100c95dff7a6546a52e86ca14560a4810aa32bc2530ae50be27926
100d49a60d58afddbae6019095628a64e9d4fb798637d277f25c52759123e80a
102ead28aad11640f46d42f5c7e94f15202ca38562de8c37a3bfbd6cb7ad12dd
10a7dd514bbfa4bd8aa3358f4330cdebc3b59658b865c66692dc66d680f1c658
10b2155331d3b0c7934808e52084c3911f82ece51f39836e3ef0e8db39ee9904
11b4c682e2712b0c6516b3800b48afb967015dae3b4a06307281539d691aee86
12129dd02feff5bdfc7b2cc1832cb68efd8a2d8caeb528d82919e55c2178dc76
122d3657eca3ae04fe7072488f6b1c1cde4225462792a5466729867437003e2d
123e6cc577073220e3cb0b7a04f64af72321ae438bbbe492af90fd83c3e68edd
12f4c1a3c604546b294d2b51461229b21c86bfbfd2e8bbd040e36a411f17f32f
131bfb49b5d80492ddcab3ec34448a445806e0c992c96eca65d42311539defe6
136f1283c0c4ff708b52d89febb3a3f457247ecbe56d22868f5bdeea60158b8c
1379e36644ac0f28d83c4c8b502d96cac61961cf6835c1e11ce214c270320d38
1440ef576d0b002306600b414a15fe71fed7658b107683882b0339cc4a82a182
16d7ba996c924f71b9bec979109680f9137df4184ae69f164efce56c89000ae1
175f436a3075c4016faad4907b7fa86c0f34851ea7ec4ce0210fb1e377258aa2
181c9610626543c859424ae029daa9f2d17b48040e65c31d61c71d0213d269b4
1947b2ed119c74a87843dc49522939e178658cb768b00948ed1cd2b28b2479ea
19acd39592c857d2605521e17b61a6ce3f2b5c6d34a3a05ea8ea4d312d37091f
1a99e83fdf9e80eb51d0ee8857632a895e5e7715ea435ead572e23fa1f7f191c
1d72dcb3abbfac1e2f0970832958bc2c2dac25d9b869b28f6dddb5fec0d45e7f
1e5a3425debcf82d2c5bf95ae4aaabb84280402b98accc2cefa6145217093ab1
239fca3f5df496aab1b7c7696aaa26d77174501abc9cb1c1e12a188584d745cc
2955a7a28f30466bfb49c60ab10c2cd14f53a4456e4b6d456c976ac088f3f942
2978aabe9e13034efa30336c2a013714a9166bd482df569d5081d70a18c22a28
2bfd2788208bebdbd027bfb1220e27b8283198e5b6f05e3e09b1fad2c8b29c8e
30aa96552ed6d03af50adcf6557a6ec3c3cb54f78fc50ee822d6d3c2bf70f9bc
31a01efe3d5484cb4f2b635c841b493fd4d9bb819457d7471135bf640d85c1ae
31db019368c71ce1ae360fccb5e4bdb511b289f5815eb74be72fc39ef49f03d2
32055b2d52f63c415e84a3b6552b02e2773ac7939674a242b4856ff441f1adbe
32d271b7df9a7bd3cae2b2d7a9db56c287ede67b2ad537d1eb41701f62c3323a
3468b520ec611e72cc9cf84c15ba791b9dd4008a2766d7ce680fe5df0bdbac35
3583f9dff6cb8c89815c821887873bbe19818a2c32c2580fb7dfdf35cc035eba
35cca711eeab74520897fa7d78a5228861e9eb0bd2f66e1aa3810784acf4f11c
35fed9b0364151ec00d8084a6189b22562cfc369fec2cc2416a08043797b1c64
37d6c01052425e77d38007224ac22921f1003ee757a8642d73e615ae0fdff254
3813efe9956fc0404d007a6d1a72c54f5db75470f36f4718c7a51d872826a13e
38a02e9cd2b875bee8e55377cbdb1905b7d07955713e4ffc20544d01a9cbe4f1
39f0a33dbcd8b68eb965d0149d744ec9a4e2028840b967c6cf47e3081e07d460
3a2adcac20af82cdb882ab9bd9a1a78ca30f833a488cd13a55daf8ff743271a3
3a770ad08848493bcd756afcfd27a79bc89962fb0caf2cd173892de3eaffaa83
3b75cbcad5615d88443317f9ccfb93a6292835db6e8a4e1f3a11bf5dc1e0eaae
3b788ad21e6bb8e9c068488f1670c500be46802b0bdc5c475df2503220cccb07
3eb85214c777bc9b173684ee6cf0de3c415bff66e06bb0d96e11937509aee552
419d14b7d31b5d505c4a67a157454756b43697e1156a1181b8e431cad3d2106f
426110407bdba9dfe5a4f6d39d6369c8baf47008d7738765c3eb7d1ee62e3344
4593a512ed7dabb6be349fc4bab80909c998261426560fc851c8ceb157446e3d
45ef1e51df38e6778aaf2cd726748b55459b4aa54a2c8c2fea445cab0885f7bc
47799b4853ffa2cb541f153f0b50fc335324a5964e04093a8316d4a62eacc8f1
4cca5e53350f2adb11cf4eb202ec7a994631014325e5bed0d040f564737eb38e
4cea65512dbdf77377eb95df694165cfdfd47a190efc64c7ebf3947415a8c08b
4d26f9475847da9db8be0d1a5553a15bd6473f3104008a3919c6b417f50c53da
4ea208842ac49499066bfbffa3b3f29b406ae2ae26a509bc0e13719b4ee2d85e
4ede1197d5311e23fc768b683d59c02ed11405ae722c5df522d2b31a452d4bcb
517d8b2852f709db4e9899576e5e1b1b848427b7e0829a7f918a6dc8875772b9
52f47ee64260116303b07638df8c2b7f71e3bf1514f44e11e89f1d3329b42235
53723a77cc0a4fa705d3e1fd3fd815786db02afbeb2a990eeb92383a9a71a9ef
537ed2ad6904c575f7eb2ea0a9bec508dea26ad8b51e58c7ddd65fa77bc2a058
538f432efeb79fc231cad11b718c20bdab951af381784208d1c66334721edec3
549ebde3daa59c044fc725c988ceced294da49053f723f31cae3a0bf9c7aa93b
562dc6b24ea581f4f285a016cab0f8243d80dfae6fb484d38533ba29972cf644
57ff043c50d16c5214746a27a9629d522787c1d2f85d3b453d8665fa94adeaf2
58dc9bfd9fb920e5e2359eb448df941c36eafa44b63b3d47466eff2f1a91b62d
591dec78016954f6762c1f06f6b94069155cbca2d643f0954ae3474c04e5473f
599b8bf3fb7fc2f44c016d0c7917152943cf3b43ea4e5e78362b130aea0ab07c
5a650c25d749796af6013e067b9c46b4e82901a4e73d5e560df4e13b51ceeb2b
5b0cfc52bc14d591f4d60211a3f5fa7db305256ce25119aa10249e966a1fda58
5bbd118658e61b2c7a841cd64b36cc0a7c707d67427c6fb6ce07e01fc4e9f257
5caa04f055398103d0fe3c9906d580372807e4579626b88c894ad2fe6765c6ca
5f291378beb7c8264918b491efa4ebc66110423efbd45ee4e1258a16f9d2a401
5f2f26cf27b0ffb53cf4a5ddec0d2fcd1236eaf7f4af3a7b78d9d23a23e4cb50
5f816f9b45889e55fc0a0c714f900968583738c6827c31f774bd45e07aec4c3f
60fef33d394d079626952dd2cb1d7bc6c28ba789116ee87d1d263e433857a856
6299f3e36dc84d0d1aa0b460cfe353d8460f8aae5b13aa75aab9d8ea2efc1a7a
640ffe74b1f7d37a7e15471f5f9f3c8a556296225b5961fcfdceb33624b000fe
64917df5f523fc7c2622a523c91223cacb4f56f28158736ade67ff4210b528e0
661b63dca6bdd7d51ec6231bc5891b029f7bd8c6fb37989212f2fdf98a0ee8c0
665981bc367a71821608c4da0f21f2fd07cc78ec740dab4c35690b68799bfc96
67a5b58d36ef0884ee86d601a72ffb085c02aa9cfa40cd3a869ea6806084a011
6ba94140ceb5ebde3137b53ac7173f99caa66b0672887705d808ed1f0508415a
6d23e4cb2a7704f3ebeaf44893bb9c1df101f0f03d522ceb51a0e1cfc7f8e8ec
6e042b1e9b57979ff67476adac3b38e7ca2a45228ef361ab0faa7d1f59072d2b
6ebdd810e46d96ffefcc9bb771377431bea8b2c31c51ae585045810cb7e826c0
6f386875b5039c4f6322daafac454769be06e1823879d6de068f415ee01893b2
6f3c24c620d2e4908ae09fc17656f0a61dafa63df181ebd8c7c5fcc3369cf7f6
7021a189f24167ad53bdfc259eee5b6f94d8413f79a0a399220504583dee8455
70502bb6c9fd88cdce1092f83ef2f6408a039c7b9de5652cd22087159dd8ba28
70bace206efc5066e6179603dc6af05a89773629eb5b00c921daad016c46f41f
717cc1c1cd1788a45027d549ae018a57f72e8f5f7586be633055c2400440b489
71e00f0a18ce6d6cd5e183b7cf13dfe659754eb939368b6a003792797c45056b
749112fd2fc84f3f5c1da92a3c8c14ff6dbacde09dd63e25a04e425ba25bab14
765baabf2cffedacadb1b683f242396bdf147f045a14e90e50cea2c164756b10
77b7fa89c446b127b0c1d8ad0c5dc5fb57c8121dd3c40a67b77e5c0a35d75114
79823c206d8b844c67dbd9db4a0345b11930b699ce1a545cea9601f9f89a51c1
799ad2e1325621191989046263aa5e431ea36eec156451afeb41aeb04afca9a9
7a0d8c4542b1e1ba4dab3b3f3fed19c02862c7b8e77732eb4c87551f09e06d29
7b601d4a67aedd2c161de142b4799032a3a298905beb96a732e4ce0157de2aa8
7b61b337fa911a993574e9094f17f0d48247551929cee1369a0259349ede3ea7
7c38161b50bfa0d62fba13ee1daaaad2a86e59fc5e9693dcaccbb29046644347
7ccf0424b23d23ba33937f84b5ebfae2391c023beb1567b7145d1df81593e1c0
82a9252b7d18acc69cff2c82b740d9b810d8a5042ef65a532b680ee4020effae
82c58393e0d855e14a9a3dadf046d823134e3d65c098146c9689df121739334b
82f755397b3e305be68747fc964dd8c5702c271bca7c85a2dbe2ca726dcafbc8
8380f95847f1a226d620c15fab7c1612f9ae7d375b78d004ed12f4ed9787faf3
838352d1425aaae03fda3d7cfcd5ed398e17bd22c6d0248ac1576aa47f4e1b52
84c802d78bf74bf211b90902ddd97a6c13589a39e5ab776e819886853609eec6
853eefbbfdc888ff893c5dfe288d8791dfa219e856e4e6ffea4a217846244614
86284f4e247cbadd3b43ad1914daaf591621d4d88b9200b500b5a7683c920e4a
883bff3bf4fa910b0842dd7ca716783b7f2f08dba9226f6e84d3f2d726ed8274
8b78178c8fd8a72412c7dcc6f381a90fbecd96d7195fb5cfc84c1a079935bff1
8f5a34f80165dd3b125af00e0f799000581693356c589931ac12a3eca44dba2d
8f7ce48631d067be88170413507cc534ca0b5dcb00d6bae77a8de7700c4f5568
8fa58f1d8bebadae9b7f4990b37984b93220efa7d516ef678cf0506e6dce772d
9037fd514562b5a5bb717551f43d2f56bd7a0e6563b35c189d80b56a24da711b
92592af7724d81176c48b78acaee5815e3327827cf8c9c1d449f27d068bb44d6
9292f7f271bcfead51e1b7acbd880d00e4b0348a5b543429db067c66a7aa2ec3
92fe26c8230e536786caaa0932023f795e94d364ef3221a728d81d7ef90afd2a
930b122390468b932430ba102ce11c672c668663e0c3d1798527bc5c75f7fbf5
94de343851ddec428f261bdce99fad1148420d7949e31c6e25ab6cbaa36218ca
9570bbdb530065408a2c3d51801fcbb4bd0e5de8ce10b71096dcc8eac4571988
958a75638f244908b46438a9b3d3b86449cdcebb6b0fce3552a1f0a31b65c9ae
978760723983e42e83dfc1d23a929d44c7edfb6631c7257df2a598603ec4e25d
9837ba70f7d9df220a25f6f3ac7cb395d09928226deec41d9d68983e6a377c27
9b5b44ded4ede28d92834c4db286780a5628d02597a739ff3633f808d47f0939
9b66bcea2cd1e6f08b4f5500a367e12c9a9f33a4ed756037d63dc2121071beda
9b8b18328c40299c8663c96d8462a5349aa21b0180c263696b174f171c82b93b
9bb6aba0ebc1593ed13ff5e00907397ac508944f95232e17e5afa194ee4c6002
9d84786f19587aff8ed8a7d7ac2def4c15969bf6f1fcaade1fd8e5d60c33f21c
9fb242a4adc557d4eb4f638c7815f58dd590fbd20e4132dbc358eadae42fe44d
a2ca137ab1650809aad7bff3029454c6e7fcdd7716b5bb6fc95822c15c208974
a4b07204b33173093041072e00e88d0083c88b88f634561aabe46ec8992f9332
a4cebe4913d275f7387b8d8b2acb7d76324550746e8802f28d432a15d3608194
a5ddd635bbbf579e865bd324329ef64b9d750c92eef0e9599e23916139a0b1c7
a7ea153cb1790d301791a424a6de0c320ec1d3eb7efdc0b71e6447e3b33fdacd
a9c005e6683d52eadd9f94e29a576ff2053a60809181619714b053002c5d2e6f
aa3f7d356fc1b9a5bd198a9cae0aaf86bba906bc51027d58b424e7caa8550723
aaee037bd7631c72f08d7d9b8261c02da2a0d7a69fd98e5b4a0d51b71d4ca89c
ab50736803967469f2a5ae5624f5e06cfd299f92ac94e255c39d0ee7bc30e40a
adb0d88a8655a39400e194d8ac9df6e6f3ac28defadf5e4a2686fbcf688bf259
af52a469ef5d9dd3b9b9c5bc1ea20c9fdd486b7c24aa7df6be3f006f82d228d6
af5562054a38fd1eef5465883393189cb1f862d6a52e85441f6efa638a8e119b
b07b89a722de05928f4f674bcb7e9901e45c29a2af387a6e8e8c12a171eb2373
b18c9e75825836541b9d7015a4a53dacddae7bb29c3bedbca9758349d9de7425
b40551ea3f577d38778a762b4983ab25ef3247f4227b30a2bc47acab8224afe5
b61808ecd5aa0c6abd3df46e1f2ec32a18fc9da837d5b7db895214d5a4745682
b68c6e9c0b287cf9d7e82707c44708f7762213b90bfe2cfbeefe4cb3f0667442
b6f457aebc800db12b08ccda58e0be7a2d15a043e9b2f10457168e9d99c9b854
b8942b158c02dd3f2b985eacd89c0947964812f01f0ecfd22f6349a130c77542
b8a97b4c697cfa9f47414d83d6dbc0bf21b52281c1d018904ebcfe52cf88a108
b98030335337f01183cc474feefbb351d45afe8263ddfcfa7fd5554b97147362
bd878970ab0cbcf5b29bf5a7e2f9ae25e81279ddc0cc30d59bdd242f40a465c2
bec324abe89a4466ea31b46a11270f69ee71fb01d6a640edaad566f589aa9ef9
c0278c21b6310485b5546d072c1703a390dcf10ad01dfbde1e1fe1e4f796d9f4
c27b6225d0b71fc9be2da1b7616f979663aced2ecd76e32814697ac027d0c282
c38440fde99869002aec2e422f28e4ba360bced59bbe6ea769d0caad763fdc6e
c4daccf0ac446a6160b18ea3fbf9ab3166ee4181c0e9a40d1c7f26702dea5a69
c4decb86958771c4332bce4748a7eb4867dd9f66258dfba85a88bc8eb1822a38
c4f6077458402ab0803226800fdcfc92c58169ce94435cd62d688588ccfe89f1
c730e6287aa786e04d22daa4e6c77b504cdf80dc4f09877a15bc79bac84403f6
c77b479ead371d060f45186dc10d6bb2c9d32aac0275de27fab94b2f65a54500
c7c057a2a841138af9f5e5d0919aa2099c27453600d87c3186896836ba812399
ca313b26bf374909bd0232772f86c613e206f33a77e7c66452429a684693c5f9
cbccb0494dc3b5ef6810a203851c68cd00cc2c397bca55898ebf82981c1ba648
cbe0ec259077679463a23abb44d85529e27d54bdc0f1c5afbf72e7f8cba4b8f2
d0d2aa0220d8d55fe5a028d41f02af236a0c5f6ad5d39054621aec63fc1bef83
d37a05507ee7da9f95d5fab0b52f03248bb3e160643c17a1e2668db80c077846
d43c6aba8577d6f6e846545d25587748ff13e676320936f4c3104ba94e22e24c
d65c564ac7ecbe786ab6f66b4a2aff57b21ef70e24d25727307d6a51a722da7e
d76b4212f4b378be4ebac39567fb86df9b1bddffabf4e041d2e45503c441914a
d85f877f8d4d56ebfe56be1f8e11d3de68632c13b258955ed52cabad19a4e783
d871694564319f19892ade1b3e34486883d95b384b1f07185bd572777303fea5
d9105bd42fdab5c865980300f0700490933fcb93aa9223e5a1051b780f036cae
db374ba72eeceb56a67ec78c6f5c98d2e454ece2e83e3c4c1b1ac044baeb2cc0
df43aec4416c5ccf985815877a169241c06edf747b5695c048665d4a40323afc
df62315f5c8cdf498cef05c05386c8fc4f994a67551f40118f5be265267a2217
dfb0266da4ad6a4334216c26cab2383155a702a1b0738be8c8e2d671e1c998e7
e168b9f5827cb011c151049535ce63362ecf08f39655485c1f3c899474d04634
e23d300d4caacb13390b018df922798b7e4de2c012670776d1a5fb45b787eb2b
e4dff6694f28d833ff1087e64c1498c9c9232abdcebf324bffdcbe322a125bb3
e56f554fbbd10426e2fc784847a2ba8c8554b4f5c6248294e6da3a5a07555ef0
e6475b9ec4e5494a4952074f2acc6352ce617dea4c39b0646e3af2a67c99fddb
e741316cdee811177ffe7b20cfdd1616cf29d63d475b5abcf4be45f0165b2095
e7611fac5c7603bc7a9f342efe76c656ed04e267192ef0620e827ebddac5520a
e83f6a6f47e7d51ad62415e6c07a5e8e9fd5408a107b9afbdba5657c9d6882c0
eafb46760c6ca2a826af095d5b71423b93ff9a0ce5e6b2369d55d51bae5ba5cd
eb185e6d132bbedd392160872e4329a96977f6d338014696fcdae3b35f195cc8
ebfc585bba8bfa8b1b8c617577a7238373fa336dd5d411dbee720dd4a906e365
ec25ebfcfee56043773ef08bafa21683befbe3f74fa39c2ff3e149a25c7831d7
ecb4832aec029ecf6342defa825866821f610695bbb132b56e44884318f44b91
ed6f85aed6c250545a123c5c3be00af5fe28018b0fe6e42fce10b9cc73afee21
ef7af4b3a2e3860e7b210b8c24dff885515573d28204053c8e4523eccfd6aa36
efe3a916d8946435407de5ca7f8110d93ad788aade74f8b83c698b5d7ae8338e
f0159cc8ce4568753a7475824095dc94555c724302a817943ae6c670cfc24c9f
f4629c7de5efbbc0047ca88cfdb4403619b94651fb01dd144cfa6283f3840cd8
f4d0e6be4fa21b836500f0254352dd10a7f5a26abebeb1e7b7980e1896570796
f6853a25abff371818a7a5852ecaf8b01482577e3f2a4eb1ca2093b739d1601c
f6c5412b5b16428b3898f8e534318b6e5e1e19981302d4301a308c8486e4e3ff
f70e37d9c9380b978df1ccb8a67f644bb7d90174c420ff4b90beb61edb9e5f99
f71822de24a50ca44db81e8529d59bc071ca457318dc5c4d35ce02a1ccef3b53
f97797ca0d80a8406dec8f939c725445742a884d734c9d339321c10e88bb4433
f994013af4ac4aec934bcbf4267a169982cd58451b2586450abf86523b301653
f9aa404e6b892570fa59a968eb1e6f2069cb6e6105632e323ae91d7c8005fe57
fa5b139ba84bcbe572db3ed6cd29793f70f2c7f77d7f60e403a91d96a06db7e8
fb085874ccc515ae84118ccfdbd9f7eaf718ff1194b0f8dbf5b62caec906516e
fb4c19ce89d08a9056fcca54a158693109901dfab61adfeaf449ca230786945f
fccaaabe6cdd5c817df1a5dd597fb210e79a509edb1c660fb2553618cacdd0da
feba095b82700027b488def99613f3de7d281a2e5fd34ead69519fc12208c883
ff426a58a852e0960291fb86f188f62bf25105280922251aa1a2d66092c43b55
ffaddaa50a635dcb4a0d8d17fc4864f65b81b09c0fa221d327d31ae42a48b26f
```

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Repetition Makes Perfect'

### Use-Case 1

The first use-case invloves 44 unique AgentTesla samples exfiltrating to IP addresses Virtual Systems LLC, two of which reside on the same /24 subnet. Another common characteristic among these samples is that none of them resolves a domain name. Additionally, the user/sender and recipient addresses are the same with the addition of "1" to the end of the recipient addresses. Finally, the passwords associated with these accounts follow the same pattern and length.

| IP Address                                  | User                                 | Recipient                             | Password       | Count |
|---------------------------------------------|--------------------------------------|---------------------------------------|----------------|-------|
| ```78.142.19.111```                         | ```brooyu@larbaxpo.com```            | ```brooyu1@larbaxpo.com```            | ```UmX3iJQg``` | 32    |
| ```78.142.19.101```                         | ```urc@emmannar.com```               | ```urc1@emmannar.com```               | ```r1NmBO4h``` | 4     |
| ```78.142.19.101```</br>```77.83.117.234``` | ```dave@emmannar.com```              | ```dave1@emmannar.com```              | ```cwEqoinR``` | 4     |
| ```78.142.19.101```</br>```77.83.117.234``` | ```pcs@deepsaeemirates.com```        | ```pcs1@deepsaeemirates.com```        | ```J3fP8xWq``` | 2     |
| ```78.142.19.101```                         | ```auth@deepsaeemirates.com```       | ```hp@deepsaeemirates.com```          | ```8txksCNY``` | 1     |
| ```78.142.19.101```                         | ```slimshades@deepsaeemirates.com``` | ```slimshades1@deepsaeemirates.com``` | ```NAEgz9DX``` | 1     |

### Use-Case 2

The second use-case belongs to the operator "strykeir". Initially, the operator operated 32 unqiue AgentTesla samples under the same user/sender/recipient addresses. The last sample under the "strykeir" domain changed the password from "iyke112@@@333" to "@@Io419090@@". At time progressed, pivoting on the latter password reveals new accounts, domains, and information stealer families. Between 2020-05-12 and 2020-05-15, the operator introduced their first observed HawkEye sample.

| Password                                   | Count    | User                           | Count | Family     |
|--------------------------------------------|----------|--------------------------------|-------|------------|
| ```iyke112@@@333```</br>```@@Io419090@@``` | 32</br>1 | ```star-origin@strykeir.com``` | 33    | AgentTesla |
| ```@@Io419090@@```                         | 11       | ```staronuegbu@yandex.com```</br>```hselimoglu@bmssrevis.com```</br>```brajesh@cropchemicals.co.in```</br>```cjmyguy@yandex.com``` | 6</br>2</br>1</br>2 | AgentTesla</br>AgentTesla</br>AgentTesla</br>HawkEye |

### Use-Case 3

The third use-case involves 6 initial AgentTesla samples with the same password of ```greateman32```. Later on, the operator appears to have decided to shift to Yandex as opposed to the custom domain, while maintaining the same password among all 9 samples.

| Password          | Count | User                                                        | Count       |
|-------------------|-------|-------------------------------------------------------------|-------------|
| ```greateman32``` | 9     | ```yyaqob@trevisqa.com```</br>```fffffffgggd@yandex.com```  | 6</br>3     |

### Use-Case 4

Another use-case of correlated passwords is the password ```wassodedon22```, which is used 17 in 17 samples with 6 different accounts. Pivoting by the domain in the account ```reallife@jpme.org.in``` reveals 5 accounts potentially linked to the same operator, all of which used PDR network for exfiltration.

| Password           | Count | User                                                                                                                                                                                          | Count                      |
|--------------------|-------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------|
| ```wassodedon22``` | 17    | ```chinaloggers@juili-tw.com```</br>```fallin@damllakimya.com```</br>```loggers@sitechukandlreland.com```</br>```money@zellico.com```</br>```thb@tbh-tw.com```</br>```reallife@jpme.org.in``` | 10</br>2</br>2</br>1</br>1 |

| Password           | Count | User                       | Count       |
|--------------------|-------|----------------------------|-------------|
| ```Ehimembano1@``` | 5     | ```fuckoff@jpme.org.in```  | 5           |

### Use-Case 5

The account ```issac@anding-tw.com``` is observed to reference two different domains with obvious similarities, allowing correlating of additional accounts and passwords.

| Domain                                                 | User                                                                                   | Count          | Password                                                                                |
|--------------------------------------------------------|----------------------------------------------------------------------------------------|----------------|-----------------------------------------------------------------------------------------|
| ```smtp.blowtac-tw.com```</br>```smtp.anding-tw.com``` | ```eileen@blowtac-tw.com```</br>```issac@anding-tw.com```</br>```dabo@anding-tw.com``` | 14</br>6</br>2 | ```FBZmjprY*6```</br>```znL#cNm1```</br>```zra1@!G8gQ+i```</br>```Daberechukwuego123``` |


### Additional Use-Cases:

| User                                                                         | Recipient                                                                                               | Password                                         | Count   | Family                 |
|------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|--------------------------------------------------|---------|------------------------|
| ```satinder@bodycarecreations.com```                                         | ```satinder@bodycarecreations.com```                                                                    | ```Lion@4321```                                  | 7       | AgentTesla             |
| ```enquiry@waman.in```                                                       | ```enquiry@waman.in```                                                                                  | ```enquiry@2020```                               | 5       | AgentTesla             |
| ```shahid@onyxfreight.com```                                                 | ```shahid@onyxfreight.com```                                                                            | ```jiashah123```                                 | 5       | AgentTesla             |
| ```onlineboxmonitor@tehnopan.rs```</br>```onlineboxmonitor@fiscalitate.eu``` | ```nwekeboxs@tehnopan.rs```</br>```nwekeboxs@fiscalitate.eu```                                          | ```;&7]PU*4yzVJ```                               | 15      | Phoenix</br>AgentTesla |
| ```accounts2@oilexindia.com```                                               | ```accounts2@oilexindia.com```                                                                          | ```Kamal@2019```                                 | 13      | AgentTesla             |
| ```snp@1st-ship.com```                                                       | ```snp@1st-ship.com```                                                                                  | ```441101474992991313053992```                   | 10      | AgentTesla             |
| ```fuckoff@jpme.org.in```                                                    | ```fuckoff@jpme.org.in```                                                                               | ```Ehimembano1@```                               | 5       | AgentTesla             |
| ```skt@startranslogistics.com```                                             | ```skt@startranslogistics.com```                                                                        | ```SIALKOT12345```                               | 10      | AgentTesla             |
| ```msg@acroative.com```                                                      | ```hm@acroative.com```</br>```nu@acroative.com```</br>```jn@acroative.com```</br>```nx@acroative.com``` | ```onegod5050()```                               | 6       | AgentTesla             |
| ```info@pat.ps```                                                            | ```info@pat.ps```                                                                                       | ```Firas2017!```                                 | 3       | AgentTesla             |
| ```elekus2020@aerotacctvn.com```                                             | ```elekus2020@aerotacctvn.com```                                                                        | ```sOeKk#E6```                                   | 9       | AgentTesla             |
| ```finance@enmark.com.my```                                                  | ```finance@enmark.com.my```                                                                             | ```08Jan1963```                                  | 3       | AgentTesla             |
| ```finance@manunggalkaroseri.com```                                          | ```finance@manunggalkaroseri.com```                                                                     | ```123572525finance```                           | 7       | AgentTesla             |
| ```tegaworks@masterindo.net```                                               | ```tegaworks@masterindo.net```                                                                          | ```Gp:b2Qgqa3*}```</br>```uLrOsjJYN9```          | 7       | AgentTesla             |
| ```ranger@canvanatransport.com```</br>```ranger@seltrabank.com```</br>```ranger2@amisglobaltransport.com```</br>```anger@canvanatransport.com```</br>```grant3@leltbank.com``` | ```ranger@canvanatransport.com```</br>```ranger@seltrabank.com```</br>```ranger2@amisglobaltransport.com```</br>```anger@canvanatransport.com```</br>```grant3@leltbank.com``` | ```newpassword216```           | 37     | AgentTesla             |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Impersonation'

This correlation invloves two different malware families under the same exfiltration domain, namely, AgentTesla and MassLogger. Interestingly, the domain appears to impersonate General Electric (GE) with the use of a look-a-like typosquatted domain. The operator of this domain started with the use of AgentTesla. However, between 2020-05-03 and 2020-05-07, the operator started utilizing MassLogger.

| User                        | Count | Domain                     | Password       | Count | Family     |
|-----------------------------|-------|----------------------------|----------------|-------|------------|
| ```slim1@ge-lndustry.com``` | 4     | ```smtp.ge-lndustry.com``` | ```J)*(EIv4``` | 4     | AgentTesla |
| ```admin@ge-lndustry.com``` | 5     | ```smtp.ge-lndustry.com``` | ```tvyTkyG1``` | 5     | MassLogger |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Steering Towards Arid Yandex Pastures'

In general, 152 samples fully abused Yandex as an exfiltration platform.

| User                                   | Password                                     | Family                    | Count |
|----------------------------------------|----------------------------------------------|---------------------------|-------|
| ```ikpc1@yandex.com```                 | ```ikechukwu112```                           | AgentTesla                | 20    |
| ```mullarwhite@yandex.com```           | ```challenge12345```                         | AgentTesla                | 10    |
| ```tim3.44@yandex.com```               | ```Obaten10```                               | AgentTesla                | 9     |
| ```staronuegbu@yandex.com```           | ```@@Io419090@@```                           | AgentTesla                | 6     |
| ```irina.macrotek@yandex.ru```         | ```hygiene@789```                            | AgentTesla                | 6     |
| ```okirinwajesus@yandex.com```         | ```07062487004```                            | AgentTesla                | 5     |
| ```johnsonpikyu@yandex.com```          | ```cr*fDaW&m@2y6u```                         | AgentTesla                | 5     |
| ```selecttools@yandex.com```           | ```biafra123```                              | AgentTesla                | 4     |
| ```petersonhouston@yandex.com```       | ```faith12AB```                              | AgentTesla                | 4     |
| ```lucinedauglas@yandex.com```         | ```myhp6000```                               | AgentTesla                | 4     |
| ```genuxpc@yandex.com```               | ```africa@@@@@```                            | AgentTesla                | 4     |
| ```chijiokejackson121@yandex.com```    | ```chijiokejackson```                        | AgentTesla                | 4     |
| ```chi.eb@yandex.com```                | ```sages101```                               | AgentTesla                | 4     |
| ```sleeves100@yandex.com```            | ```@Sleeves100```                            | AgentTesla                | 3     |
| ```rose.nunez@yandex.ru```             | ```lochmann2```                              | AgentTesla                | 3     |
| ```r.tome@yandex.com```                | ```qwerty123@@```                            | AgentTesla                | 3     |
| ```p.origin@yandex.com```              | ```Loverboy123```                            | AgentTesla                | 3     |
| ```fxxxfuz@yandex.com```               | ```genesis070```                             | AgentTesla                | 3     |
| ```fffffffgggd@yandex.com```           | ```greatman32```                             | AgentTesla                | 3     |
| ```zecospiritual101@yandex.com```      | ```07030452451```                            | AgentTesla                | 2     |
| ```resultbox042@yandex.com```          | ```OGOM12345```                              | AgentTesla                | 2     |
| ```result.package@yandex.ru```         | ```Blessing123```                            | AgentTesla                | 2     |
| ```petersonhouston@yandex.com```       | ```faith12AB```                              | AgentTesla                | 2     |
| ```lightmusic12345@yandex.ru```        | ```chibuike12345@@@@@```                     | AgentTesla                | 2     |
| ```cruizjames@yandex.ru```             | ```cruizjamesvhjkl@```                       | AgentTesla                | 2     |
| ```cjmyguy@yandex.com```               | ```@@Io419090@@```                           | HawkEye                   | 2     |
| ```chinapeace@yandex.com```            | ```chibuikelightwork1```                     | AgentTesla                | 2     |
| ```Goodluck2k20@yandex.com```          | ```Pl@nedon1234```                           | AgentTesla                | 2     |
| ```pauline.vostropiatova@yandex.com``` | ```kaka1234@1@1```                           | AgentTesla                | 1     |
| ```boymouse@yandex.com```              | ```333link00win```                           | AgentTesla</br>HawkEye    | 2     |
| ```annwilso@yandex.com```              | ```theoldlady```</br>```HueCycle```          | AgentTesla                | 2     |
| ```zhu.china@yandex.com```             | ```KOSI213141```                             | AgentTesla                | 1     |
| ```vipa.agraindustry1@yandex.com```    | ```chosen@@@123456```</br>```chosen@@@123``` | MassLogger</br>AgentTesla | 2     |
| ```victormuller10@yandex.com```        | ```Mummy212```                               | AgentTesla                | 1     |
| ```sly-originlogs@yandex.ru```         | ```JesusChrist007```                         | AgentTesla                | 1     |
| ```pauline.vostropiatova@yandex.com``` | ```kaka1234@1@1```                           | AgentTesla                | 1     |
| ```oriego1@yandex.ru```                | ```Ijeomam288```                             | AgentTesla                | 1     |
| ```mor440ney@yandex.com```             | ```castor123@```                             | HawkEye                   | 1     |
| ```mobile.mailer@yandex.com```         | ```qwerty123@```                             | AgentTesla                | 1     |
| ```magagraceman@yandex.ru```           | ```tonero4417```                             | HawkEye                   | 1     |
| ```jessicafaithjessica@yandex.com```   | ```123abc1!```                               | AgentTesla                | 1     |
| ```james.cho8282@yandex.com```         | ```klassic1993```                            | AgentTesla                | 1     |
| ```iykelog1@yandex.com```              | ```Conversation2```                          | AgentTesla                | 1     |
| ```iren159k@yandex.com```              | ```Protected@123```                          | AgentTesla                | 1     |
| ```info.pana@yandex.com```             | ```user@12345```                             | AgentTesla                | 1     |
| ```import22.export@yandex.com```       | ```khalifa2019```                            | AgentTesla                | 1     |
| ```genaral1122@yandex.ru```            | ```kukeremaster1122```                       | AgentTesla                | 1     |
| ```freshclinton8269@yandex.com```      | ```fresh826699```                            | AgentTesla                | 1     |
| ```frank.got@yandex.ru```              | ```godson00```                               | AgentTesla                | 1     |
| ```cupjul@yandex.com```                | ```esut96092```                              | HawkEye                   | 1     |
| ```blr@saharaexpress.com```            | ```Sahara*542```                             | AgentTesla                | 1     |
| ```acksonjogodo121@yandex.com```       | ```jacksonjogodo```                          | AgentTesla                | 1     |
| ```account.info1000@yandex.com```      | ```4canada1A@```                             | AgentTesla                | 1     |
| ```Alibabalogs657@yandex.com```        | ```austinmilla```                            | AgentTesla                | 1     |



Other operators opted to exfiltrate to Yandex recipient accounts without using Yandex as for the user/sender accounts. Yet, different user/sender accounts send to the same Yandex recipient account. An example is the accounts ```charlesxmoni@yandex.com``` and ```stanleybox@yandex.com```, which appears to belong to the same operator.

| Recipient                         | User                                                                                                                           | Password                                                                             | Family                                                  | Count                  |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|---------------------------------------------------------|------------------------|
| ```vicky.br0wn@yandex.com```      | ```zainab@almushrefcoop.com```                                                                                                 | ```zainab123```                                                                      | AgentTesla                                              | 8                      |
| ```charlesxmoni@yandex.com```     | ```info@jaccontracting.com```</br>```ijaz@hsisteels.com```</br>```zafar@guddupak.com```                                        | ```#07_WAKvjLG]```</br>```Azizgroup@2018```</br>```imzafar75```                      | AgentTesla</br>MassLogger</br>AgentTesla                | 2</br>1</br>1          |
| ```stanleybox@yandex.com```       | ```zafar@guddupak.com```</br>```info@jaccontracting.com```</br>```kshitij@activepumps.com```</br>```kshitij@activepumps.com``` | ```imzafar75```</br>```#07_WAKvjLG]```</br>```X5=KN(JJIXso```</br>```X5=KN(JJIXso``` | AgentTesla</br>AgentTesla</br>AgentTesla</br>MassLogger | 1</br>1</br>2</br>1    |
| ```esime77@yandex.com```          | ```info@mondastudio.com```</br>```sales@asplparts.com```                                                                       | ```Nigels1975!```</br>```f3nu6R4lH```                                                | AgentTesla                                              | 2</br>1                |
| ```boxblessings7744@yandex.com``` | ```emingles@ilclaw.com.ph```                                                                                                   | ```P@ssw0rd```                                                                       | AgentTesla                                              | 1                      |
| ```logsdetails0@yandex.com```     | ```lot1567@okgrocer.co.za```                                                                                                   | ```Theunis@123```                                                                    | AgentTesla                                              | 1                      |
| ```morrishome1@yandex.com```      | ```limcor@le-belt.co.za```                                                                                                     | ```bemi6ERe```                                                                       | AgentTesla                                              | 1                      |
| ```ffangfang@yandex.com```        | ```info@excellent.ba```                                                                                                        | ```Ilidza_1322```                                                                    | AgentTesla                                              | 1                      |
| ```billionvain@yandex.com```      | ```supin@daiphatfood.com.vn```                                                                                                 | ```jn&6kG~_w;;A```                                                                   | AgentTesla                                              | 1                      |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Gmail Abuse'

Several operators and families abused Gmail sender/recipient accounts for data exfiltration.

| Sender                                                                   | Recipient                                                                                    | Password                                  | Fmaily     |
|--------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|-------------------------------------------|------------|
| ```regan10586@gmail.com```                                               | ```regan10586@gmail.com```                                                                   | ```231father```                           | MassLogger |
| ```fletcherjohnsgt@gmail.com```                                          | ```fletcherjohnsgt@gmail.com```                                                              | ```moneymustdrop```                       | MassLogger |
| ```sanbrith112@gmail.com```                                              | ```sanbrith112@gmail.com```                                                                  | ```pointaz45```                           | MassLogger |
| ```2020@website-practise.site```</br>```practice@webdesign-class.site``` | ```sumayyah.diijlafood@gmail.com```</br>```jplorrder@gmail.com```                            | ```Best4666##@@```</br>```A$sfxcedvcc1``` | AgentTesla |
| ```saleem@ejazontheweb.com```                                            | ```nisanelactricals.pro@gmail.com```</br>```hoke.sales01@gmail.com```                        | ```t%[D2FmSeQezu,}e```                    | AgentTesla |
| ```testing@bhavnatutor.com```                                            | ```gabandtee@gmail.com```                                                                    | ```Onyeoba111```                          | Phoenix    |
| ```postmaster@unitedparcelsservices.com```                               | ```jameshamilton7544@gmail.com```                                                            | ```Dw1e7Tlo1id```                         | AgentTesla |
| ```tou013@efx.net.nz```                                                  | ```ourplastic22@gmail.com```                                                                 | ```etou01315```                           | AgentTesla |
| ```pulsit.c@spinteng.com```</br>```varahi@varahi.in```                   | ```lightbabamusic@gmail.com```                                                               | ```Spie#th2017```</br>```Pass@#2019```    | Phoenix    |
| ```lal@montaneshipping.com```                                            | ```pedroalex716@gmail.com```</br>```hoke.sales01@gmail.com```</br>```i.sibrmiov@gmail.com``` | ```Montanemumbai*@*@*@321```              | AgentTesla |
| ```bellalice897@gmail.com```                                             | ```bellalice897@gmail.com```                                                                 | ```Germany777@@```                        | MassLogger |
| ```proyectos@santiagogarcia.es```                                        | ```miguelipscc@gmail.com```</br>```nurifrost556@gmail.com```                                 | ```964Arantza&&??@68```                   | AgentTesla |
| ```bellalice897@gmail.com```                                             | ```bellalice897@gmail.com```                                                                 | ```Germany777@@```                        | MassLogger |
| ```ratna@askon.co.id```                                                  | ```scdcytc@gmail.com```                                                                      | ```r4tn41226```                           | AgentTesla |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'The Shifters'

Based on accounts and passwords analysis and correlation, many actors are observed to alternate malware families, more recently, M00nDev and MassLogger stealers. While the data in this correlation may be repetitive, it highlights the operators accessibility and persistence. Correlations are not inclusive of all samples operated by the same group.

- Between 2020-04-29 and 2020-05-02, the 'ROBO' operators started utilizing M00nD3v.
- Between 2020-05-11 and 2020-05-13, the same operators started utilizing MassLogger. See [The 'ROBO' Gang (Formerly: Correlation 'Fire Them')](#the-robo-gang-formerly-correlation-fire-them) for samples associated with this opertator.

  | User                        | Password            | Family     | Shifts            |
  |-----------------------------|---------------------|------------|-------------------|
  | ```billions@cairoways.me``` | ```Whyworry90#```   | M00nD3v    | After 2020-04-29  |
  | ```admin@cairoways.me```    | ```requestShow@```  | M00nD3v    | After 2020-04-29  |
  | ```billions@cairoways.me``` | ```Whyworry90#```   | HawkEye    | Before 2020-04-29 |
  | ```admin@cairoways.me```    | ```requestShow@```  | AgentTesla | Before 2020-04-29 |
  | ```billions@cairoways.me``` | ```Whyworry90#```   | AgentTesla | Before 2020-04-29 |
  | ```billions@cairoways.me``` | ```Whyworry90#```   | MassLogger | After 2020-05-11  |
  | ```admin@cairoways.me```    | ```requestShow@```  | MassLogger | After 2020-05-11  |

- Between 2020-05-03 and 2020-05-07, the operator under the Impersonation' correlation started utilizing MassLogger keylogger. See [Correlation 'Impersonation'](#correlation-impersonation) for samples associated with this opertator.

  | User                        | Domain                     | Password       | Family     | Shifts            |
  |-----------------------------|----------------------------|----------------|------------|-------------------|
  | ```slim1@ge-lndustry.com``` | ```smtp.ge-lndustry.com``` | ```J)*(EIv4``` | AgentTesla | Before 2020-05-03 |
  | ```admin@ge-lndustry.com``` | ```smtp.ge-lndustry.com``` | ```tvyTkyG1``` | MassLogger | After 2020-05-03  |

- Between 2020-05-05 and 2020-05-08, the operator of the "tashpita" domain started utilizing MassLogger keylogger. The opertor configered the MassLogger sample to perform both, FTP and SMTP exfiltration. Previously, the operator utilized FTP-based AgentTesla exclusively. See [Correlation 'I Speak FTP Only'](#correlation-i-speak-ftp-only) for samples associated with this opertator.

  | Domain                 | Count | IP Address         | Count |
  |------------------------|-------|--------------------|-------|
  | ```ftp.tashipta.com``` | 10    | ```103.21.59.28``` | 11    |

  | Password            | User                                                    | Fmaily     | Protocol | Shifts            |
  |---------------------|---------------------------------------------------------|------------|----------|-------------------|
  | ```server1123455``` | ```server@tashipta.com```                               | AgentTesla | FTP      | Before 2020-05-05 |
  | ```router11477```   | ```router11477@tashipta.com```                          | AgentTesla | FTP      | Before 2020-05-05 |
  | ```server1543211``` | ```server1@tashipta.com```                              | AgentTesla | FTP      | Before 2020-05-05 |
  | ```success2020```   | ```mails@tashipta.com```</br>```server1@tashipta.com``` | AgentTesla | FTP      | Before 2020-05-05 |
  | ```prosperity1```   | ```xmoni@tashipta.com```                                | AgentTesla | FTP      | Before 2020-05-05 |
  | ```@Success$2020``` | ```xmoni-w@tashipta.com```                              | MassLogger | FTP      | After 2020-05-05  |
  | ```moneymustdrop``` | ```fletcherjohnsgt@gmail.com```                         | MassLogger | SMTP     | After 2020-05-05  |

- Between 2020-05-30 and 2020-06-01, the operator of "flood-protection" domain started utilizing MassLogger after 22 samples of AgentTesla. See [Correlation 'Why even bother?'](#correlation-why-even-bother) for more samples associated with this opertator.

  | User                              | Password         | Family     | Shifts            |
  |-----------------------------------|------------------|------------|-------------------|
  | ```sender@flood-protection.org``` | ```kelex2424@``` | AgentTesla | Before 2020-05-30 |
  | ```sender@flood-protection.org``` | ```kelex2424@``` | MassLogger | After 2020-05-30  |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Encrypt or not to Encrypt'

25 unique AgentTesla samples exfiltrating to a Saudi domain associated with 3 IP addresses, two of which are adjacent, and all of them belonging to Hetzner Online GmbH. The operator(s) appear to encrypt SMTP with one account but not the other, despite the fact that their passwords simply swtich word locations, suggesting that both accounts belong to the same operator(s). The last account with 3 observed samples slightly changed the password in an uninnovative way, further tying the sample with the same operator(s).

* Registrant Org: مصنع وضوح الشرق للحديد (Bright East Steel Factory)
* Registrant Country: المملكة العربية السعودية (Kingdom of Saudia Arabia)
* Tech Contact: وضحي محمد (Wadhi Mohammed)

| Domain                  | Count | IP Address            | Count |
|-------------------------|-------|-----------------------|-------|
| ```mail.besco.com.sa``` | 22    | ```136.243.194.254``` | 15    |
|                         |       | ```46.4.159.174```    | 7     |
| ```besco.com.sa```      | 3     | ```136.243.194.253``` | 2     |
|                         |       | ```136.243.194.254``` | 1     |

| User                         | Count | Password                 | Count |
|------------------------------|-------|--------------------------|-------|
| ```khalid@besco.com.sa```    | 16    | ```besco2020admin```     | 16    |
| ```pavan@besco.com.sa```     | 6     | ```admin2020besco```     | 6     |
| ```al_ghamaz@besco.com.sa``` | 3     | ```admin2000besco2005``` | 3     |

| User                         | SMTPS | Count |
|------------------------------|-------|-------|
| ```khalid@besco.com.sa```    | false | 15    |
| ```khalid@besco.com.sa```    | true  | 1     |
| ```pavan@besco.com.sa```     | true  | 6     |
| ```al_ghamaz@besco.com.sa``` | false | 3     |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Why even bother?'

The uses cases in this correlation demonstrate that some operators attempted to hide their repetitive offenses by using different sender/recipient accounts, domains, and passwords among different malware families, with a great failure rate.

### Use-Case 1

| User                          | Count | Password | Recipient                                                                                                                                                                                       | Family     |
|-------------------------------|-------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| ```ikostadinov@cargoair.bg``` | 10    | 334455   |```info@agri-chernicals.net```</br>```grace_pan@traingle-cn.com```</br>```e.pezzli@giivin.com```</br>```stan@iskreameco.com```</br>```brunolugnani@arrmet.in```</br>```neo.ycwang@mindroy.com``` | AgentTesla |

### Use-Case 2

| IP Address          | Count | Domain               | User                               | Count | Password                 | Family     |
|---------------------|-------|----------------------|------------------------------------|-------|--------------------------|------------|
| ```162.241.27.33``` | 26    | ```mail.platinships.net``` | ```amani@platinships.net```</br>```armani@platinships.net```</br>```garang@platinships.net```</br>```phyno@platinships.net```</br>```chima@platinships.net```</br>```don@platinships.net```   | 2</br>4</br>5</br>6</br>5</br>1     | ```Azz%LcQK%sb!```</br>```#%c,*lVZNIXctE.!BA```</br>```%izARl@$-zHKEYwlHM```</br>```J~5v.F5[G06H6}ct{!```</br>```R[2](NaueJp!6tL?sW```</br>```Vn,?+Es5;dNayEvk]*```       | AgentTesla |
|                     |       | ```mail.novaa-ship.com```  | ```ebase@novaa-ship.com```</br>```flo@novaa-ship.com```</br>```armani@novaa-ship.com``` | 1</br>1</br>1</br>     | ```O-xgNxpHw~?h5H.ZEB```</br>```KyayQQ{Kn$TJ+f;dRd```</br>```Azz%LcQK%sb!``` | AgentTesla</br>AgentTesla</br>HawkEye |

### Use-Case 3

| IP Address           | Count | Domain                          | User                              | Password         | Count    | Family     |
|----------------------|-------|---------------------------------|-----------------------------------|------------------|----------|------------|
| ```85.187.154.178``` | 26    | ```mail.flood-protection.org``` | ```clark@flood-protection.org```  | ```clark2424@``` | 3        | AgentTesla |
|                      |       |                                 | ```fido@flood-protection.org```   | ```fido2424@```  | 3        | AgentTesla |
|                      |       |                                 | ```sender@flood-protection.org``` | ```kelex2424@``` | 10</br>2 | AgentTesla</br> MassLoggger |
|                      |       |                                 | ```somc@flood-protection.org```   | ```somc2424@```  | 2        | AgentTesla |
|                      |       |                                 | ```wale@flood-protection.org```   | ```wale2424@```  | 2        | AgentTesla |
|                      |       |                                 | ```udug@flood-protection.org```   | ```udug2424@```  | 1        | AgentTesla |
|                      |       |                                 | ```sepp@flood-protection.org```   | ```sepp2424@```  | 2        | AgentTesla |
|                      |       |                                 | ```dom@flood-protection.org```    | ```dom2424@```   | 1        | AgentTesla |

### Use-Case 4

Same operator attempted to change by using the "kingmezz" domain, though everything else is almost the same.

| User                     | Count | Password                | Family     |
|--------------------------|-------|-------------------------|------------|
| ```urch@damienzy.xyz```  | 5     | ```@damienzy.xyz2240``` | AgentTesla |
| ```david@damienzy.xyz``` | 4     | ```@damienzy.xyz2240``` | AgentTesla |
| ```ck@kingmezz.xyz```    | 1     | ```@kingmezz.xyz```     | AgentTesla |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'FTP vs. SMTP'

This group of operators alernates between SMTP and FTP exfiltration under the same domain. Each domain has two sub-domains based on the exfiltration path configured in the sample.

### Use-Case 1

| Domain                                         | Count   | IP Address         | Count |
|------------------------------------------------|---------|--------------------|-------|
| ```mail.flyxop.com```</br>```ftp.flyxpo.com``` | 8</br>5 | ```67.225.141.8``` | 13    |

| User                   | Count | Password               | Count | Protocol |
|------------------------|-------|------------------------|-------|----------|
| ```stan@flyxpo.com```  | 10    | ```schenkerokani123``` | 8     | FTP      |
| ```kene@flyxpo.com```  | 5     | ```success2020@```     | 3     | SMTP     |
| ```xmweb@flyxpo.com``` | 5     | ```Success0803959```   | 2     | SMTP     |

### Use-Case 2

| Domain                                                                           | Count   | IP Address          | Count |
|----------------------------------------------------------------------------------|---------|---------------------|-------|
| ```mail.scandinavian-collection.com```</br>```ftp.scandinavian-collection.com``` | 1</br>2 | ```206.72.205.67``` | 3     |

| User                                  | Count | Password                                   | Count   | Protocol     |
|---------------------------------------|-------|--------------------------------------------|---------|--------------|
| ```may@scandinavian-collection.com``` | 3     | ```kR6d.DFet#7w```</br> ```=piYR_r.%[Ch``` | 1</br>2 | SMTP</br>FTP |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'I Speak FTP Only'

Operators in this correlation solely utilize FTP for exfiltration in their samples. One exception to this rule is the operator "tashipta", and only when they shifted from AgentTesla to MassLogger. In the MassLogger sample, the operator configured both, FTP and SMTP (abusing Gmail) exfiltration.

| Domain                 | Count | IP Address         | Count |
|------------------------|-------|--------------------|-------|
| ```ftp.tashipta.com``` | 10    | ```103.21.59.28``` | 11    |

| Password            | Count | User                                                    | Count   | Fmaily     | Protocol |
|---------------------|-------|---------------------------------------------------------|---------|------------|----------|
| ```server1123455``` | 3     | ```server@tashipta.com```                               | 3       | AgentTesla | FTP      |
| ```router11477```   | 2     | ```router11477@tashipta.com```                          | 2       | AgentTesla | FTP      |
| ```server1543211``` | 2     | ```server1@tashipta.com```                              | 2       | AgentTesla | FTP      |
| ```success2020```   | 2     | ```mails@tashipta.com```</br>```server1@tashipta.com``` | 1</br>1 | AgentTesla | FTP      |
| ```prosperity1```   | 1     | ```xmoni@tashipta.com```                                | 1       | AgentTesla | FTP      |
| ```@Success$2020``` | 1     | ```xmoni-w@tashipta.com```                              | 1       | MassLogger | FTP      |
| ```moneymustdrop``` | 1     | ```fletcherjohnsgt@gmail.com```                         | 1       | MassLogger | SMTP     |

Additional FTP-based samples.

| Domain                           | Count | IP Address            | User                                                     | Password                                  | Family                 |
|----------------------------------|-------|-----------------------|----------------------------------------------------------|-------------------------------------------|------------------------|
| ```ftp.kassohome.com.tr```       | 4     | ```95.130.175.151```  | ```bringlogs@kassohome.com.tr```                         | ```J%jCb2L=!5~E```                        | AgentTesla</br>HawkEye |
| ```ftp.fox8live.com```           | 3     | ```207.191.38.36```   | ```production```                                         | ```pr0duct10n```                          | AgentTesla             |
| ```ftp.trirekaperkasa.com```     | 2     | ```139.162.57.218```  | ```trirek@trirekaperkasa.com```                          | ```^CuvfABJJ1OM```                        | AgentTesla             |
| ```ftp.hustle360.a2hosted.com``` | 2     | ```68.66.248.24```    | ```kftp@hustle360.a2hosted.com```                        | ```-szG^tj_nEpo```                        | AgentTesla             |
| ```ftp.exploits.site```          | 2     | ```199.188.206.58```  | ```bbstar@exploits.site```</br>```milli@exploits.site``` | ```{Zo3Dn4H#3G)```</br>```)J@i^p#%m4*N``` | AgentTesla             |
| ```files.000webhost.com```       | 2     | ```145.14.145.53```   | ```plein-air-adhesives```                                | ```dragonflam123```                       | HawkEye                |
| ```ftp.aydangroup.com.my```      | 2     | ```43.252.214.149```  | ```original@aydangroup.com.my```                         | ```^l@2~))DQq,z```                        | AgentTesla             |
| ```ftp.filelog.info```           | 1     | ```162.213.253.54```  | ```Burna@filelog.info```                                 | ```^{Opb6h,rjW^```                        | HawkEye                |
| ```ftp.faltelecom.com```         | 1     | ```43.255.154.108```  | ```faltelecom@faltelecom.com```                          | ```Playboy@11```                          | HawkEye                |
| ```ftp.eloelokendi.com```        | 1     | ```107.172.93.44```   | ```hhhpp@eloelokendi.com```                              | ```boygirl654321```                       | HawkEye                |
| ```ftp.connectus-trade.net```    | 1     | ```104.247.74.6```    | ```one@connectus-trade.net```                            | ```o^Z0CIU?^yL2```                        | AgentTesla             |
| ```ftp.nedtek.com.au```          | 1     | ```116.0.23.212```    | ```abs00001@nedtek.com.au```                             | ```philomina1234567890```                 | AgentTesla             |
| ```ftp.talleresmartos.com```     | 1     | ```149.202.247.154``` | ```ntums@talleresmartos.com```                           | ```alibaba.com```                         | MassLogger             |

[Top](#information-stealers-wall-of-sheep-analysis)

## Information Stealers HTTP Panels

Some samples opted to exfiltrate via HTTP only, or both HTTP and SMTP.

| Family     | MD5                                    | Exfil. URL                                                              | Panel URL                                                                    | IP:Port                |
|------------|----------------------------------------|-------------------------------------------------------------------------|------------------------------------------------------------------------------|------------------------|
| M00nD3v    | ```10e2d3c8c81501b0b70f6cdf8ea5c872``` | ```http://ark.makinghapen.com/api.php```                                | ```http://ark.makinghapen.com/?signin```                                     | ```104.28.24.79:80```  |
| MassLogger | ```e52e5dd7cd8cda6e283f96a76a5f4855``` | ```http://yatesassociates.co.za/panel/upload.php```                     | ```http://yatesassociates.co.za/panel/login/index.php```                     | ```196.41.127.42:80``` |
| MassLogger | ```14a59177297e9458dafa83ef55acd445``` | ```https://drngetu.co.za/fruit/panel/upload.php```                      | ```https://drngetu.co.za/fruit/panel/login/index.php```                      | ```154.0.175.94:443``` |
| MassLogger | ```eaa8776e7fe85e8f5f8e240a94ff0eaf``` | ```https://baileybluesclothing.com/themes/wind/images/ukr/upload.php``` | ```https://baileybluesclothing.com/themes/wind/images/ukr/login/index.php``` | ```68.66.216.8:443```  |


- ```10e2d3c8c81501b0b70f6cdf8ea5c872```
  ![image](https://github.com/ditekshen/is-wos/raw/master/img/m00ndev_panel_10e2d3c8c81501b0b70f6cdf8ea5c872.png)

- ```e52e5dd7cd8cda6e283f96a76a5f4855```
  ![image](https://github.com/ditekshen/is-wos/raw/master/img/masslogger_panel_e52e5dd7cd8cda6e283f96a76a5f4855.png)

- ```14a59177297e9458dafa83ef55acd445```
  ![image](https://github.com/ditekshen/is-wos/raw/master/img/masslogger_panel_14a59177297e9458dafa83ef55acd445.png)

- ```eaa8776e7fe85e8f5f8e240a94ff0eaf```
  ![image](https://github.com/ditekshen/is-wos/raw/master/img/masslogger_panel_eaa8776e7fe85e8f5f8e240a94ff0eaf.png)

[Top](#information-stealers-wall-of-sheep-analysis)
