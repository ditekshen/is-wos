## Correlation 'Repetition Makes Perfect'

### Use-Case 1

44 unique samples distributed between AgentTesla and AgentTesla that do not issue DNS queries as part of therir C&C as seen in the "Top 10 Domains" table. 42 samples exfiltrate to two IP addresses on the same /24 subnet on Virtual Systems LLC. Emails addresses, particularly the user and recipient addresses as well as passwords follow the same patterns, potenially linking all 43 samples to the same operator.

| IP Address    | Count |
|---------------|-------|
| 77.83.117.234 | 2     |
| 78.142.19.101 | 10    |
| 78.142.19.111 | 32    |
  
| User                           | Recipient                       | Password | Count |
|--------------------------------|---------------------------------|----------|-------|
| brooyu@larbaxpo.com            | brooyu1@larbaxpo.com            | UmX3iJQg | 32    |
| urc@emmannar.com               | urc1@emmannar.com               | r1NmBO4h | 4     |
| dave@emmannar.com              | dave1@emmannar.com              | cwEqoinR | 4     |
| pcs@deepsaeemirates.com        | pcs1@deepsaeemirates.com        | J3fP8xWq | 2     |
| auth@deepsaeemirates.com       | hp@deepsaeemirates.com          | 8txksCNY | 1     |
| slimshades@deepsaeemirates.com | slimshades1@deepsaeemirates.com | NAEgz9DX | 1     |

### Additional Use-Cases

| User                            | Recipient                      | Password                 | Count | Family              |
|---------------------------------|--------------------------------|--------------------------|-------|---------------------|
| satinder@bodycarecreations.com  | satinder@bodycarecreations.com | Lion@4321                | 7     | AgentTesla          |
| enquiry@waman.in                | enquiry@waman.in               | enquiry@2020             | 5     | AgentTesla          |
| shahid@onyxfreight.com          | shahid@onyxfreight.com         | jiashah123               | 5     | AgentTesla          |
| onlineboxmonitor@tehnopan.rs    | nwekeboxs@tehnopan.rs          | ;&7]PU*4yzVJ             | 7     | Phoenix, AgentTesla |
| onlineboxmonitor@fiscalitate.eu | nwekeboxs@fiscalitate.eu       | ;&7]PU*4yzVJ             | 7     | AgentTesla          |
| accounts2@oilexindia.com        | accounts2@oilexindia.com       | Kamal@2019               | 13    | AgentTesla          |
| snp@1st-ship.com                | snp@1st-ship.com               | 441101474992991313053992 | 8     | AgentTesla          |
| fuckoff@jpme.org.in             | fuckoff@jpme.org.in            | Ehimembano1@             | 5     | AgentTesla          |
| skt@startranslogistics.com      | skt@startranslogistics.com     | SIALKOT12345             | 7     | AgentTesla          |
| msg@acroative.com               | hm@acroative.com               | onegod5050()             | 2     | AgentTesla          |
|                                 | nu@acroative.com               | onegod5050()             | 2     | AgentTesla          |
|                                 | jn@acroative.com               | onegod5050()             | 1     | AgentTesla          |
|                                 | nx@acroative.com               | onegod5050()             | 1     | AgentTesla          |
| info@pat.ps                     | info@pat.ps                    | Firas2017!               | 2     | AgentTesla          |


## Correlation 'Fire Them'

The operators in this correlation mostly utilize HawkEye with 34 unique samples. Between 2020-03-19/20 and 2020-03-24/25 and forward, the operators started utilizing AgentTesla with 13 unique samples. The accounts and passwords used across both families overlap. The operators are also active in creating new accounts and regularly changing passwords of existing accounts. If you work with or hire these operators, quit or fire them, they are already costing you money.

Between 2020-04-29 and 2020-05-02, the operators potentially introdcued a new keylogger known as __M00nD3v__ based on on password analysis and correlation. The same password 'Whyworry90#' is observed in previous HawkEye and AgentTesla samples operated by the same group. This keylogger appears to have been announced on April 17, 2020. Only 4 samples are currently observed and all of them are run by the same operator where the accounts/passwords are used across HawkEye and AgentTesla.

Between 2020-05-11 and 2020-05-13, the operators utilizing __MassLogger__ keylogger, which was initially added on 2020-05-07. The same account and password 'Whyworry90#' is observed in previous AgentTesla, HawkEye, and M00nD3d samples operated by the same group.

MassLogger Samples:

| User                                   | Count | Password         |
|----------------------------------------|-------|------------------|
| billions@cairoways.me                  | 4     | Whyworry90#      |
| billions@cairoways.me                  | 2     | MOREMONEY123     |
| finance@supreme-sg.icu                 | 2     | biggod1234@      |
| binu@metalfabme.icu                    | 2     | @Mexico1.,       |
| gestionesolleciti@pec-warrantgroup.icu | 2     | NoisyGeneration# |
| admin@cairoways.me                     | 2     | requestShow@     |
| mpa@cairoways.me                       | 2     | BLESSEDyear20    |
| mpa@cairoways.me                       | 1     | NewBlessings     |
| uz@cairoways.me                        | 1     | 09012345@        |
| uz@cairoways.me                        | 1     | pAsSword@#1      |
| aboyo@akonuchenwam.org                 | 1     | fySnrmX9         |
| dogman@akonuchenwam.org                | 1     | HaLzYAY8         |
| mobite@akonuchenwam.org                | 1     | )^nveCU9         |
| manman@akonuchenwam.org                | 1     | QMvStW^7         |
| martinze@akonuchenwam.org              | 1     | (SLYNY(3         |
| nednwoko@akonuchenwam.org              | 1     | mMtRZHe4         |
| obuman@akonuchenwam.org                | 1     | H*XyvM)5         |
| obino@akonuchenwam.org                 | 1     | dho)YOW7         |
| abu@akonuchenwam.org                   | 1     | i^*Moaf0         |
| wiz@metalfabme.icu                     | 1     | Whyworry#@       |
| bob@metalfabme.icu                     | 1     | @Mexico1.,       |
| tina.meng@wingsun-chine.com            | 1     | @Mexico1.,       |
| lchandra@bazciproduct.com              | 1     | whywori#@#       |
| docs@hdtrans.me                        | 1     | @A120741#        |
| s.ewaldt@otv-international.me          | 1     | 1234567890       |
| huangjianping@chinacables.icu          | 1     | whyworry1090#    |
| info23@huatengaccessfloor.icu          | 2     | @Mexico1.,       |
| ampall@ampail.com                      | 1     | 1234567890       |
| imports@techin.icu                     | 1     | 1234567890       |
| info23@huatengaccessfloor.icu          | 1     | 1234567890       |
| admin@bazciproduct.com                 | 1     | @123098#         |

M00nD3v Samples:

| User                          | Count | Password         |
|-------------------------------|-------|------------------|
| billions@cairoways.me         | 3     | Whyworry90#      |
| billions@cairoways.me         | 1     | MOREMONEY123     |
| admin@cairoways.me            | 1     | requestShow@     |
| finance@supreme-sg.icu        | 1     | biggod1234@      |
| huangjianping@chinacables.icu | 1     | whyworry1090#    |
| sales001@cairoways.me         | 1     | whyworry01#      |
| ampall@ampail.com             | 1     | 123098322@#      |
| inkyu@dubhe-kr.icu            | 1     | SometimesINLIFE@ |
| docs@hdtrans.me               | 1     | @A120741#        |
| s.ewaldt@otv-international.me | 1     | 1234567890       |

HawkEye Samples:

| User                         | Count | Password          |
|------------------------------|-------|-------------------|
| produccion@servalec-com.me   | 4     | biggod1234        |
|                              |       | BIGgod1234        |
|                              |       | @bongo1.,         |
| success@poylone.com          | 3     | @qwerty12345      |
| wetground@poylone.com        | 3     | @qwerty12345      |
| charif.yassin@cronimet.me    | 3     | @mile31.,         |
| panos@skepsis-sg.icu         | 2     | @Bongo1.,         |
|                              |       | breakinglimit@    |
| service@ptocs.xyz            | 2     | bigGod1234@       |
| gavin@jandregon.com          | 2     | WHYworry??#       |
| yosra.gamal@csatolin.com     | 2     | @Mexico1.,        |
|                              |       | HELPmeLORD@       |
| stephanie.giet@technsiem.com | 1     | Whyworry90#       |
| parisa@abarsiava.com         | 1     | @Mexico1.,        |
| jplunkett@bellfilght.com     | 1     | biggod12345@      |
| ikuku@poylone.com            | 1     | GODhelpme@#       |
| sav@emeco.icu                | 1     | GodsPlan@#        |
| raphael@gitggn.com           | 1     | @mexico1.,        |
| v.clemens@slee-de.me         | 1     | @mexico1.,        |
| sale@somakinya.com           | 1     | Wenenighty.,      |
| xu@weifeng-fulton.com        | 1     | @bongo1.,         |
| jamit@cairoways.icu          | 1     | breakinglimit100% |
| billions@cairoways.me        | 1     | Whyworry90#       |
| accounts@friendships-ke.icu  | 1     | INGODWETRUST      |
| dcaicedo@igihm.icu           | 1     | STAYSAFE123       |
| ahmadi@gheytarencarpet.com   | 1     | Focus$Pray        |

AgentTesla Samples:

| User                         | Count | Password      |
|------------------------------|-------|---------------|
| jplunkett@bellfilght.com     | 2     | biggod12345@  |
| dcaicedo@igihm.icu           | 2     | MOREMONEY123  |
| charif.yassin@cronimet.me    | 1     | @mile31.,     |
| gavin@jandregon.com          | 1     | WHYworry??#   |
| stephanie.giet@technsiem.com | 1     | Whyworry90#   |
| ikuku@poylone.com            | 3     | BLESSEDchild@ |
|                              |       | GodAbegOo#    |
|                              |       | HELPmeLORD@   |
| yosra.gamal@csatolin.com     | 1     | HELPmeLORD@   |
| billions@cairoways.me        | 2     | Whyworry90#   |
| admin@cairoways.me           | 1     | requestShow@  |
| finance@supreme-sg.icu       | 1     | biggod1234@   |

## Correlation 'Impersonation'

4 uniqe AgentTesla samples, potentially attempting to impersonate General Electric (GE) with the use of a look-a-like typosquatted domain. This operator introduced new keylogger known as MassLogger using the same domain name, but with differnt account and password.

| User                  | Count | Domain               | Password | Count | Family |
|-----------------------|-------|----------------------|----------|-------|------------|
| slim1@ge-lndustry.com | 4     | smtp.ge-lndustry.com | J)*(EIv4 | 4     | AgentTesla |
| admin@ge-lndustry.com | 2     | smtp.ge-lndustry.com | tvyTkyG1 | 5     | MassLogger |

## Correlation 'Steering Towards Arid Yandex Pastures'

### Use-Case 1

The operator strykeir is prolific. One of the samples used a different password. Pivoting on this password reveals that the same password is also used with different accounts. On 2020-05-14, the password '@@Io419090@@' was observed with a new HawkEye sample.

| User                           | Count | Password      | Count |
|--------------------------------|-------|---------------|-------|
| star-origin@strykeir.com       | 33    | iyke112@@@333 | 32    |
|                                |       | @@Io419090@@  | 1     |

| User                        | Count | Family     | Password     | Count |
|-----------------------------|-------|------------| -------------|-------|
| staronuegbu@yandex.com      | 6     | AgentTesla | @@Io419090@@ | 11    |
| hselimoglu@bmssrevis.com    | 2     | AgentTesla |              |       |
| brajesh@cropchemicals.co.in | 1     | AgentTesla |              |       |
| star-origin@strykeir.com    | 1     | AgentTesla |              |       |
| cjmyguy@yandex.com          | 1     | HawkEye    |              |       |

### Use-Case 2

Another sample shifting to Yandex is the operator of the trevisqa domain. With only 9 unique AgentTesla samples sharing the same account password, the shift occured from the custom account in 6 samples to 2 more recent samples with Yandex.

| User                   | Count | Password     | Count |
|------------------------|-------|--------------|-------|
| yyaqob@trevisqa.com    | 6     | greateman32  | 9     |
| fffffffgggd@yandex.com | 3     |              |       |


In general, 119 AgentTesla and 3 HawkEye samples rely on Yandex for data exfiltration.

| User                           | Password            | Family              | Count |
|--------------------------------|---------------------|---------------------|-------|
| ikpc1@yandex.com               | ikechukwu112        | AgentTesla          | 12    |
| mullarwhite@yandex.com         | challenge12345      | AgentTesla          | 10    |
| tim3.44@yandex.com             | Obaten10            | AgentTesla          | 9     |
| staronuegbu@yandex.com         | @@Io419090@@        | AgentTesla          | 6     |
| okirinwajesus@yandex.com       | 07062487004         | AgentTesla          | 5     |
| johnsonpikyu@yandex.com        | cr*fDaW&m@2y6u      | AgentTesla          | 5     |
| selecttools@yandex.com         | biafra123           | AgentTesla          | 4     |
| genuxpc@yandex.com             | africa@@@@@         | AgentTesla          | 4     |
| chijiokejackson121@yandex.com  | chijiokejackson     | AgentTesla          | 4     |
| chi.eb@yandex.com              | sages101            | AgentTesla          | 4     |
| sleeves100@yandex.com          | @Sleeves100         | AgentTesla          | 3     |
| rose.nunez@yandex.ru           | lochmann2           | AgentTesla          | 3     |
| r.tome@yandex.com              | qwerty123@@         | AgentTesla          | 3     |
| p.origin@yandex.com            | Loverboy123         | AgentTesla          | 3     |
| lucinedauglas@yandex.com       | myhp6000            | AgentTesla          | 3     |
| fxxxfuz@yandex.com             | genesis070          | AgentTesla          | 3     |
| fffffffgggd@yandex.com         | greatman32          | AgentTesla          | 3     |
| zecospiritual101@yandex.com    | 07030452451         | AgentTesla          | 2     |
| resultbox042@yandex.com        | OGOM12345           | AgentTesla          | 2     |
| lightmusic12345@yandex.ru      | chibuike12345@@@@@  | AgentTesla          | 2     |
| Goodluck2k20@yandex.com        | Pl@nedon1234        | AgentTesla          | 2     |
| boymouse@yandex.com            | 333link00win        | AgentTesla, HawkEye | 2     |
| zhu.china@yandex.com           | KOSI213141          | AgentTesla          | 1     |
| sly-originlogs@yandex.ru       | JesusChrist007      | AgentTesla          | 1     |
| oriego1@yandex.ru              | Ijeomam288          | AgentTesla          | 1     |
| mor440ney@yandex.com           | castor123@          | HawkEye             | 1     |
| mobile.mailer@yandex.com       | qwerty123@          | AgentTesla          | 1     |
| jessicafaithjessica@yandex.com | 123abc1!            | AgentTesla          | 1     |
| james.cho8282@yandex.com       | klassic1993         | AgentTesla          | 1     |
| iykelog1@yandex.com            | Conversation2       | AgentTesla          | 1     |
| irina.macrotek@yandex.ru       | hygiene@789         | AgentTesla          | 1     |
| iren159k@yandex.com            | Protected@123       | AgentTesla          | 1     |
| info.pana@yandex.com           | user@12345          | AgentTesla          | 1     |
| import22.export@yandex.com     | khalifa2019         | AgentTesla          | 1     |
| genaral1122@yandex.ru          | kukeremaster1122    | AgentTesla          | 1     |
| freshclinton8269@yandex.com    | fresh826699         | AgentTesla          | 1     |
| frank.got@yandex.ru            | godson00            | AgentTesla          | 1     |
| cupjul@yandex.com              | esut96092           | HawkEye             | 1     |
| cjmyguy@yandex.com             | @@Io419090@@        | HawkEye             | 1     |
| chinapeace@yandex.com          | chibuikelightwork1  | AgentTesla          | 1     |
| blr@saharaexpress.com          | Sahara*542          | AgentTesla          | 1     |
| acksonjogodo121@yandex.com     | jacksonjogodo       | AgentTesla          | 1     |
| account.info1000@yandex.com    | 4canada1A@          | AgentTesla          | 1     |
| Alibabalogs657@yandex.com      | austinmilla         | AgentTesla          | 1     |
| annwilso@yandex.com            | theoldlady          | AgentTesla          | 1     |
| annwilso@yandex.com            | HueCycle            | AgentTesla          | 1     |

Other operators opted to exfiltrate to Yandex recipient without using Yandex as accounts

| User                    | Recipient                   | Password     | Family              | Count |
|-------------------------|-----------------------------|--------------|---------------------|-------|
| zafar@guddupak.com      | charlesxmoni@yandex.com     | imzafar75    | AgentTesla          | 1     |
| kshitij@activepumps.com | stanleybox@yandex.com       | X5=KN(JJIXso | AgentTesla          | 1     |
| info@jaccontracting.com | stanleybox@yandex.com       | #07_WAKvjLG] | AgentTesla          | 1     |
| info@mondastudio.com    | esime77@yandex.com          | Nigels1975!  | AgentTesla          | 1     |
| emingles@ilclaw.com.ph  | boxblessings7744@yandex.com | P@ssw0rd     | AgentTesla          | 1     |
| lot1567@okgrocer.co.za  | logsdetails0@yandex.com     | Theunis@123  | AgentTesla          | 1     |
| limcor@le-belt.co.za    | morrishome1@yandex.com      | bemi6ERe     | AgentTesla          | 1     |
| info@excellent.ba       | ffangfang@yandex.com        | Ilidza_1322  | AgentTesla          | 1     |

## Correlation 'God is Great'

27 unique samples distributed among HawkEye, AgentTesla and AgentTesla, respectively, had religiously themed passwords, with specific patterns that potentially tie the accounts to the same operator. This is particularly evident when the origins of samples are correlated to the same source(s). No God condones theft, stealing, or crime.

| User                        | Count | Password            | Count | Family                 |
|-----------------------------|-------|---------------------|-------|------------------------|
| ikuku@poylone.com           | 4     | GODhelpme@#         | 1     | HawkEye                |
|                             |       | BLESSEDchild@       | 1     | AgentTesla             |
|                             |       | GodAbegOo#          | 1     | AgentTesla             |
|                             |       | HELPmeLORD@         | 1     | AgentTesla             |
| yosra.gamal@csatolin.com    | 1     | HELPmeLORD@         | 2     | HawkEye                |
| produccion@servalec-com.me  | 3     | biggod1234          | 2     | HawkEye                |
|                             |       | BIGgod1234          | 1     | HawkEye                |
| jplunkett@bellfilght.com    | 3     | biggod12345@        | 3     | HawkEye, AgentTesla    |
| jasmine@cinco.icu           | 3     | Biggod1234          | 2     | HawkEye                |
|                             |       | biggod1234          | 1     | HawkEye                |
| elber@wtsele.net            | 2     | .,?!miracleGod12345 | 2     | AgentTesla             |
| imports@eastendfood-uk.icu  | 2     | GodGrace6665555     | 2     | HawkEye                |
| carolyne@dandopub.mu        | 2     | OhMyGod#357         | 2     | AgentTesla             |
| service@ptocs.xyz           | 2     | bigGod1234@         | 2     | HawkEye                |
| sav@emeco.icu               | 1     | GodsPlan@#          | 1     | HawkEye                |
| frank.got@yandex.ru         | 1     | godson00            | 1     | AgentTesla             |
| accounts@friendships-ke.icu | 1     | INGODWETRUST        | 1     | HawkEye                |
| contact@assocham.icu        | 1     | GODSGRACE123        | 1     | HawkEye                |
| ahmadi@gheytarencarpet.com  | 1     | Focus$Pray          | 1     | HawkEye                |
| sly-originlogs@yandex.ru    | 1     | JesusChrist007      | 1     | AgentTesla             |
| msg@acroative.com           | 6     | onegod5050()        | 6     | AgentTesla             |
| mpa@cairoways.me            | 1     | NewBlessings        | 1     | MassLogger             |
| finance@supreme-sg.icu      | 2     | biggod1234@         | 2     | MassLogger, AgentTesla |

## Correlation 'Why even bother?'

Some operators attempted to hide thier repetitive offenses by using different recipient addresses, domains, or accounts and passwords as demonestrated in the below two uses cases.

### Use-Case 1

| User                    | Count | Password | Recipient                 | Family     |
|-------------------------|-------|----------|---------------------------|------------|
| ikostadinov@cargoair.bg | 10    | 334455   | info@agri-chernicals.net  | AgentTesla |
|                         |       |          | grace_pan@traingle-cn.com |            |
|                         |       |          | e.pezzli@giivin.com       |            |
|                         |       |          | stan@iskreameco.com       |            |
|                         |       |          | brunolugnani@arrmet.in    |            |
|                         |       |          | neo.ycwang@mindroy.com    |            |

### Use-Case 2

| IP Address    | Count | Domain               | User                   | Count | Password           | Family     |
|---------------|-------|----------------------|------------------------|-------|--------------------|------------|
| 162.241.27.33 | 25    | mail.platinships.net | amani@platinships.net  | 2     | Azz%LcQK%sb!       | AgentTesla |
|               |       | mail.platinships.net | amani@platinships.net  | 1     | #%c,*lVZNIXctE.!BA | AgentTesla |
|               |       | mail.platinships.net | garang@platinships.net | 4     | %izARl@$-zHKEYwlHM | AgentTesla |
|               |       | mail.platinships.net | phyno@platinships.net  | 6     | J~5v.F5[G06H6}ct{! | AgentTesla |
|               |       | mail.platinships.net | chima@platinships.net  | 5     | R[2](NaueJp!6tL?sW | AgentTesla |
|               |       | mail.platinships.net | don@platinships.net    | 1     | Vn,?+Es5;dNayEvk]* | AgentTesla |
|               |       | mail.novaa-ship.com  | ebase@novaa-ship.com   | 1     | O-xgNxpHw~?h5H.ZEB | AgentTesla |
|               |       | mail.novaa-ship.com  | flo@novaa-ship.com     | 1     | KyayQQ{Kn$TJ+f;dRd | AgentTesla |
|               |       | mail.novaa-ship.com  | armani@novaa-ship.com  | 1     | Azz%LcQK%sb!       | HawkEye    |

### Use-Case 3

| IP Address     | Count | Domain                    | User                        | Count | Password   | Family     |
|----------------|-------|---------------------------|-----------------------------|-------|------------|------------|
| 85.187.154.178 | 15    | mail.flood-protection.org | clark@flood-protection.org  | 3     | clark2424@ | AgentTesla |
|                |       | mail.flood-protection.org | fido@flood-protection.org   | 3     | fido2424@  | AgentTesla |
|                |       | mail.flood-protection.org | sender@flood-protection.org | 4     | kelex2424@ | AgentTesla |
|                |       | mail.flood-protection.org | somc@flood-protection.org   | 2     | somc2424@  | AgentTesla |
|                |       | mail.flood-protection.org | wale@flood-protection.org   | 2     | wale2424@  | AgentTesla |
|                |       | mail.flood-protection.org | udug@flood-protection.org   | 1     | udug2424@  | AgentTesla |

### Use-Case 4

Same operator attempted to change by using the "kingmezz" domain, though everything else is almost the same.

| User                    | Count | Password          | Domain                | Family     |
|-------------------------|-------|-------------------|---------------------- |------------|
| urch@damienzy.xyz       | 5     | @damienzy.xyz2240 | mail.privateemail.com | AgentTesla |
| david@damienzy.xyz      | 4     | @damienzy.xyz2240 | mail.privateemail.com | AgentTesla |
| ck@kingmezz.xyz         | 1     | @kingmezz.xyz     | mail.privateemail.com | AgentTesla |

### Use-Case 5

| IP Address | Count | Domain         | User                          | Count | Password     | Recipient                     | Family     |
|------------|-------|----------------|-------------------------------|-------|--------------|-------------------------------|------------|
| 74.208.5.2 | 9     | smtp.ionos.com | 2020@website-practise.site    | 6     | Best4666##@@ | sumayyah.diijlafood@gmail.com | AgentTesla |
|            |       | smtp.ionos.com | best-success@pure-energy.site | 2     | Best4666$$   | best-success@pure-energy.site | AgentTesla |
|            |       | smtp.ionos.com | practice@webdesign-class.site | 1     | Best4666##@@ | sumayyah.diijlafood@gmail.com | AgentTesla |
| 74.208.5.8 | 1     | smtp.ionos.mx  | reclutamiento1@cosea.mx       | 1     | 4l3ly2019.#  | reclutamiento1@cosea.mx       | AgentTesla |

## Correlation '.,'

Some samples, mostly HawkEye, associated with the same actor alternated the accounts as well as the paswords used for exfiltration. Yet, the passwords still followed the same pattern, not to mention the origins of these samples.

| User                          | Count | Password     | Family              |
|-------------------------------|-------|--------------|---------------------|
| charif.yassin@cronimet.me     | 5     | @mile31.,    | HawkEye, AgentTesla |
| binu@metalfabme.icu           | 3     | @Mexico1.,   | MassLogger          |
| xu@weifeng-fulton.com         | 3     | @bongo1.,    | HawkEye             |
| produccion@servalec-com.me    | 2     | @bongo1.,    | HawkEye             |
| info23@huatengaccessfloor.icu | 2     | @Mexico1.,   | MassLogger          |
| info@friendships-ke.icu       | 1     | @bongo1.,    | HawkEye             |
| panos@skepsis-sg.icu          | 1     | @Bongo1.,    | HawkEye             |
| michellej@fernsturm.com       | 1     | @Ranger1.,   | AgentTesla          |
| raphael@gitggn.com            | 1     | @mexico1.,   | HawkEye             |
| v.clemens@slee-de.me          | 1     | @mexico1.,   | HawkEye             |
| parisa@abarsiava.com          | 1     | @Mexico1.,   | HawkEye             |
| yosra.gamal@csatolin.com      | 1     | @Mexico1.,   | HawkEye             |
| sale@somakinya.com            | 1     | Wenenighty., | HawkEye             |
| bob@metalfabme.icu            | 1     | @Mexico1.,   | MassLogger          |
| tina.meng@wingsun-chine.com   | 1     | @Mexico1.,   | MassLogger          |



## Correlation 'Encrypt or not to Encrypt'

25 unique AgentTesla samples exfiltrating to a Saudi domain associated with 3 IP addresses, all belonging to Hetzner Online GmbH, and two of them are adjacent, appear to encrypt SMTP with one account but not the other, despite the fact that their passwords simply swtich word locations, suggesting that both accounts belonging to the same operator.

* Registrant Org: مصنع وضوح الشرق للحديد (Bright East Steel Factory)
* Registrant Country: المملكة العربية السعودية (Kingdom of Saudia Arabia)
* Tech Contact: وضحي محمد (Wadhi Mohammed)

| Domain            | Count | IP Address      | Count |
|-------------------|-------|-----------------|-------|
| mail.besco.com.sa | 22    | 136.243.194.254 | 15    |
|                   |       | 46.4.159.174    | 7     |
| besco.com.sa      | 3     | 136.243.194.253 | 2     |
|                   |       | 136.243.194.254 | 1     |

| User                   | Count | Password           | Count |
|------------------------|-------|--------------------|-------|
| khalid@besco.com.sa    | 16    | besco2020admin     | 16    |
| pavan@besco.com.sa     | 6     | admin2020besco     | 6     |
| al_ghamaz@besco.com.sa | 3     | admin2000besco2005 | 3     |

| User                   | SMTPS | Count |
|------------------------|-------|-------|
| khalid@besco.com.sa    | false | 15    |
| khalid@besco.com.sa    | true  | 1     |
| pavan@besco.com.sa     | true  | 6     |
| al_ghamaz@besco.com.sa | false | 3     |

## Correlation 'FTP vs. SMTP'

### Use-Case 1

The operator of the flyxpo domain with unique 13 AgentTesla samples and C&C to single IP address on Liquid Web, L.L.C, exclusively. The operator alternates between FTP and SMTP for exfiltration, each of which has their own sub-domain, aptly named, ftp and mail.

| Domain          | Count | IP Address   | Count |
|-----------------|-------|--------------|-------|
| mail.flyxop.com | 8     | 67.225.141.8 | 13    |
| ftp.flyxpo.com  | 5     |              |       |

| User             | Count | Password         | Count |
|------------------|-------|------------------|-------|
| stan@flyxpo.com  | 10    | schenkerokani123 | 8     |
| kene@flyxpo.com  | 5     | success2020@     | 3     |
| xmweb@flyxpo.com | 5     | Success0803959   | 2     |

| User             | Domain           | Count |
|------------------|------------------|-------|
| stan@flyxpo.com  | ftp.flyxpo.com   | 8     |
| kene@flyxpo.com  | mail.flyxpo.com  | 3     |
| xmweb@flyxpo.com | mail.flyxpo.com  | 2     |


### Use-Case 2

| Domain                           | Count | IP Address    | Count |
|----------------------------------|-------|---------------|-------|
| mail.scandinavian-collection.com | 1     | 206.72.205.67 | 3     |
| ftp.scandinavian-collection.com  | 2     |               |       |

| User                             | Count | Password         | Count | Protocol |
|----------------------------------|-------|------------------|-------|----------|
| may@scandinavian-collection.com  | 1     | kR6d.DFet#7w     | 1     | SMTP     |
| may@scandinavian-collection.com  | 2     | =piYR_r.%[Ch     | 2     | FTP      |



## Correlation 'I Speak FTP Only'

The 10 samples evenly distributed between HawkEye and AgentTesla exfiltrating to the "__tashipta__" domain only do so over FTP. Only a signle aptly named sub-domain associating to a single IP address are used. Almost all passwords relate to their respective account. The operator of the "__tashipta__" started using MassLogger keylogger configuring the same sample (a8c1496f2eecd879518ecd9e4963be33f44d759bf71e888505a35615f8eaf438) with both, FTP and SMTP exfiltration 

| Domain          | Count | IP Address   | Count |
|-----------------|-------|--------------|-------|
| ftp.tashipta.com | 10    | 103.21.59.28 | 11    |

| Password      | Count | User                      | Count | Fmaily     | Protocol |
|---------------|-------|---------------------------|-------|------------|----------|
| server1123455 | 3     | server@tashipta.com       | 3     | AgentTesla | FTP      |
| router11477   | 2     | router11477@tashipta.com  | 2     | AgentTesla | FTP      |
| server1543211 | 2     | server1@tashipta.com      | 2     | AgentTesla | FTP      |
| success2020   | 2     | mails@tashipta.com        | 1     | AgentTesla | FTP      |
|               |       | server1@tashipta.com      | 1     | AgentTesla | FTP      |
| prosperity1   | 1     | xmoni@tashipta.com        | 1     | AgentTesla | FTP      |
| @Success$2020 | 1     | xmoni-w@tashipta.com      | 1     | MassLogger | FTP      |
| moneymustdrop | 1     | fletcherjohnsgt@gmail.com | 1     | MassLogger | SMTP     |


Other FTP-based AgentTesla samples.

| Domain                     | Count | IP Address     | User                        | Password      |
|----------------------------|-------|----------------|-----------------------------|---------------|
| ftp.fox8live.com           | 3     | 207.191.38.36  | production                  | pr0duct10n    |
| ftp.trirekaperkasa.com     | 2     | 139.162.57.218 | trirek@trirekaperkasa.com   | ^CuvfABJJ1OM  |
| ftp.hustle360.a2hosted.com | 2     | 68.66.248.24   | kftp@hustle360.a2hosted.com | -szG^tj_nEpo  |
| ftp.exploits.site          | 2     | 199.188.206.58 | bbstar@exploits.sitem       | {Zo3Dn4H#3G)  |
|                            |       |                | milli@exploits.site         | )J@i^p#%m4*N  |
| files.000webhost.com       | 2     | 145.14.145.53  | plein-air-adhesives         | dragonflam123 |
| ftp.filelog.info           | 1     | 162.213.253.54 | Burna@filelog.info          | ^{Opb6h,rjW^  |
| ftp.filelog.info           | 1     | 162.213.253.54 | Burna@filelog.info          | ^{Opb6h,rjW^  |
| ftp.faltelecom.com         | 1     | 43.255.154.108 | faltelecom@faltelecom.com   | Playboy@11    |
| ftp.eloelokendi.com        | 1     | 107.172.93.44  | hhhpp@eloelokendi.com       | boygirl654321 |
| ftp.connectus-trade.net    | 1     | 104.247.74.6   | one@connectus-trade.net     | o^Z0CIU?^yL2  |

## Correlation 'The Shifters'

The data in this correlation may be repetitive. It's goal is to highlight how existing AgentTesla / HawkEye operators are shifting to newly added keyloggers, namely, __m00nD3v__ and __MassLogger__. Below are correlated samples and not inclusive of all samples operated by the same group of operators.

- Between 2020-04-29 and 2020-05-02, the operators under the 'Fire Them' correlation starting utilizing __M00nD3v__ keylogger. Between 2020-05-11 and 2020-05-13, the operators also started utilizing __MassLogger__.

  | User                         | Count | Password          | Count | Family     | Shifts           |
  |------------------------------|-------|---------------|-------|------------|------------------|
  | billions@cairoways.me        | 3     | Whyworry90#   | 3     | M00nD3v    | After 2020-04-29 |
  | admin@cairoways.me           | 1     | requestShow@  | 1     | M00nD3v    | After 2020-04-29 |
  | billions@cairoways.me        | 1     | Whyworry90#   | 3     | HawkEye    | After 2020-04-29 |
  | admin@cairoways.me           | 1     | requestShow@  | 1     | AgentTesla | After 2020-04-29 |
  | billions@cairoways.me        | 1     | Whyworry90#   | 1     | AgentTesla | After 2020-04-29 |
  | billions@cairoways.me        | 3     | Whyworry90#   | 3     | MassLogger | After 2020-05-11 |
  | admin@cairoways.me           | 1     | requestShow@  | 1     | MassLogger | After 2020-05-11 |

- Between 2020-05-03 and 2020-05-07, the operator under the Impersonation' correlation started utilizing __MassLogger__ keylogger.

  | User                  | Count | Domain               | Password | Count | Family     | Shifts            |
  |-----------------------|-------|----------------------|----------|-------|------------|-------------------|
  | slim1@ge-lndustry.com | 4     | smtp.ge-lndustry.com | J)*(EIv4 | 4     | AgentTesla | Before 2020-05-03 |
  | admin@ge-lndustry.com | 2     | smtp.ge-lndustry.com | tvyTkyG1 | 2     | MassLogger | After 2020-05-03  |

- Between 2020-05-05 and 2020-05-08, the operator of the "__tashpita__" domain under the 'I Speak FTP Only' correlation started utilizing __MassLogger__ keylogger. The opertor in this case configured the sample for both FTP and SMTP exfiltration.

  | Password      | Count | User                      | Count | Fmaily     | Protocol | Shifts            |
  |---------------|-------|---------------------------|-------|------------|----------|-------------------|
  | server1123455 | 3     | server@tashipta.com       | 3     | AgentTesla | FTP      | Before 2020-05-05 |
  | router11477   | 2     | router11477@tashipta.com  | 2     | AgentTesla | FTP      | Before 2020-05-05 |
  | server1543211 | 2     | server1@tashipta.com      | 2     | AgentTesla | FTP      | Before 2020-05-05 |
  | success2020   | 2     | mails@tashipta.com        | 1     | AgentTesla | FTP      | Before 2020-05-05 |
  |               |       | server1@tashipta.com      | 1     | AgentTesla | FTP      | Before 2020-05-05 |
  | prosperity1   | 1     | xmoni@tashipta.com        | 1     | AgentTesla | FTP      | Before 2020-05-05 |
  | @Success$2020 | 1     | xmoni-w@tashipta.com      | 1     | MassLogger | FTP      | After 2020-05-05  |
  | moneymustdrop | 1     | fletcherjohnsgt@gmail.com | 1     | MassLogger | SMTP     | After 2020-05-05  |

## Correlation 'Gmail Abuse'

| Sender                               | Recipient                      | Account                              | Password               | Fmaily     |
|--------------------------------------|--------------------------------|--------------------------------------|------------------------|------------|
| regan10586@gmail.com                 | regan10586@gmail.com           | regan10586@gmail.com                 | 231father              | MassLogger |
| fletcherjohnsgt@gmail.com            | fletcherjohnsgt@gmail.com      | fletcherjohnsgt@gmail.com            | moneymustdrop          | MassLogger |
| sanbrith112@gmail.com                | sanbrith112@gmail.com          | sanbrith112@gmail.com                | pointaz45              | MassLogger |
| 2020@website-practise.site           | sumayyah.diijlafood@gmail.com  | 2020@website-practise.site           | Best4666##@@           | AgentTesla |
| practice@webdesign-class.site        | sumayyah.diijlafood@gmail.com  | practice@webdesign-class.site        | Best4666##@@           | AgentTesla |
| saleem@ejazontheweb.com              | nisanelactricals.pro@gmail.com | saleem@ejazontheweb.com              | t%[D2FmSeQezu,}e       | AgentTesla |
| saleem@ejazontheweb.com              | hoke.sales01@gmail.com         | saleem@ejazontheweb.com              | t%[D2FmSeQezu,}e       | AgentTesla |
| testing@bhavnatutor.com              | gabandtee@gmail.com            | testing@bhavnatutor.com              | Onyeoba111             | Phoenix    |
| postmaster@unitedparcelsservices.com | jameshamilton7544@gmail.com    | postmaster@unitedparcelsservices.com | Dw1e7Tlo1id            | AgentTesla |
| tou013@efx.net.nz                    | ourplastic22@gmail.com         | tou013@efx.net.nz                    | etou01315              | AgentTesla |
| pulsit.c@spinteng.com                | lightbabamusic@gmail.com       | pulsit.c@spinteng.com                | Spie#th2017            | Phoenix    |
| varahi@varahi.in                     | lightbabamusic@gmail.com       | varahi@varahi.in                     | Pass@#2019             | Phoenix    |
| lal@montaneshipping.com              | pedroalex716@gmail.com         | lal@montaneshipping.com              | Montanemumbai*@*@*@321 | AgentTesla |
|                                      | hoke.sales01@gmail.com         |                                      |                        | AgentTesla |
|                                      | i.sibrmiov@gmail.com           |                                      |                        | AgentTesla |

#AS20200521