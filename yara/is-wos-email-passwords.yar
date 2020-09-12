rule ISWOS_Indicator_Email_Password {
    meta:
        author = "ditekshen"
        description = "passowrds from the accounts used in SMTP(S)/FTP"
        source = "https://github.com/ditekshen/is-wos"
        revision = "20200904"
        fp = "high"
    strings:
        $password1 = "07030452451" fullword ascii wide
        $password2 = "07062487004" fullword ascii wide
        $password3 = "#07_WAKvjLG]" fullword ascii wide
        $password4 = "08Jan1963" fullword ascii wide
        $password5 = "09012345@" fullword ascii wide
        $password6 = "098765432><A@" fullword ascii wide
        $password7 = "111aaa" fullword ascii wide
        $password8 = "@123098#" fullword ascii wide
        $password9 = "123098322@#" fullword ascii wide
        $password10 = "1234567890" fullword ascii wide
        $password11 = "1234567891" fullword ascii wide
        $password12 = "123572525finance" fullword ascii wide
        $password13 = "123abc1!" fullword ascii wide
        $password14 = "123$ysalgado" fullword ascii wide
        $password15 = "125875.jUkT" fullword ascii wide
        $password16 = "1Bicicleta+Viento" fullword ascii wide
        $password17 = "1q2w3e4" fullword ascii wide
        $password18 = "1q2w3e4r" fullword ascii wide
        $password19 = "1q2w3e4r5t" fullword ascii wide
        $password20 = "1q2w3e4x" fullword ascii wide
        $password21 = "1q2w3e4xx" fullword ascii wide
        $password22 = "1qa2ws3ed" fullword ascii wide
        $password23 = "1Z3mTwgv" fullword ascii wide
        $password24 = "22june1969" fullword ascii wide
        $password25 = "231father" fullword ascii wide
        $password26 = ":234Qzdem8n::" fullword ascii wide
        $password27 = "333link00win" fullword ascii wide
        $password28 = "334455" fullword ascii wide
        $password29 = "3eN13579?" fullword ascii wide
        $password30 = "3En13579?" fullword ascii wide
        $password31 = "%4:3bawcHJg@" fullword ascii wide
        $password32 = "441101474992991313053992" fullword ascii wide
        $password33 = "4canada1A@" fullword ascii wide
        $password34 = "?4cr8pS$Wa_t" fullword ascii wide
        $password35 = "4l3ly2019.#" fullword ascii wide
        $password36 = "506g239R" fullword ascii wide
        $password37 = "67brooke66" fullword ascii wide
        $password38 = "71c7eb1f8baa88" fullword ascii wide
        $password39 = "7213575aceACE@" fullword ascii wide
        $password40 = "7213575aceACE@#$" fullword ascii wide
        $password41 = "*7BFOjey!nvc]" fullword ascii wide
        $password42 = "%7JA(Z)RqC)is" fullword ascii wide
        $password43 = ";&7]PU*4yzVJ" fullword ascii wide
        $password44 = "7#Sjsj*ebT+2" fullword ascii wide
        $password45 = "{8K3~pTtbxy{" fullword ascii wide
        $password46 = ".8@%KnZgV%N#" fullword ascii wide
        $password47 = "8txksCNY" fullword ascii wide
        $password48 = "8z^mW$.fLKm2" fullword ascii wide
        $password49 = "90YbiTCCE&x%" fullword ascii wide
        $password50 = "964Arantza&&??@68" fullword ascii wide
        $password51 = "@A120741#" fullword ascii wide
        $password52 = "?A4$!,SpMP@YwVn0qV" fullword ascii wide
        $password53 = "$#)]a8ixMQdE" fullword ascii wide
        $password54 = "abcdGOODNESS123" fullword ascii wide
        $password55 = "Abobo123#" fullword ascii wide
        $password56 = "Accounts$678" fullword ascii wide
        $password57 = "acct1@0321" fullword ascii wide
        $password58 = "aditya@311274" fullword ascii wide
        $password59 = "admin1ABC223@##!con" fullword ascii wide
        $password60 = "admin2000besco2005" fullword ascii wide
        $password61 = "admin2020besco" fullword ascii wide
        $password62 = "a*~dSQ1QRg)3" fullword ascii wide
        $password63 = "africa@@@@@" fullword ascii wide
        $password64 = "Ai12457800Ai@@" fullword ascii wide
        $password65 = "Ai124578Ai@" fullword ascii wide
        $password66 = "Alberta0403" fullword ascii wide
        $password67 = "alibaba.com" fullword ascii wide
        $password68 = "AMBTfCKx2" fullword ascii wide
        $password69 = "anderson6686" fullword ascii wide
        $password70 = "anggur08*" fullword ascii wide
        $password71 = "anosky90" fullword ascii wide
        $password72 = "anyanwu3116" fullword ascii wide
        $password73 = "aqua042!" fullword ascii wide
        $password74 = "ArBgL&%27" fullword ascii wide
        $password75 = "asBTgS@1" fullword ascii wide
        $password76 = "A$sfxcedvcc1" fullword ascii wide
        $password77 = "ashatravel2017" fullword ascii wide
        $password78 = "AugustBlessings@" fullword ascii wide
        $password79 = "austinmilla" fullword ascii wide
        $password80 = "Azizgroup@2018" fullword ascii wide
        $password81 = "Azz%LcQK%sb!" fullword ascii wide
        $password82 = "Be}@Au!hv09k" fullword ascii wide
        $password83 = "bemi6ERe" fullword ascii wide
        $password84 = "besco2020admin" fullword ascii wide
        $password85 = "Best4666$$" fullword ascii wide
        $password86 = "Best4666##@@" fullword ascii wide
        $password87 = "biafra123" fullword ascii wide
        $password88 = "biggod1234" fullword ascii wide
        $password89 = "biggod1234@" fullword ascii wide
        $password90 = "bigGod1234@" fullword ascii wide
        $password91 = "Biggod1234" fullword ascii wide
        $password92 = "BIGgod1234" fullword ascii wide
        $password93 = "BIGGOD1234" fullword ascii wide
        $password94 = "biggod12345@" fullword ascii wide
        $password95 = "BILLIONLOGS123" fullword ascii wide
        $password96 = "bird0006" fullword ascii wide
        $password97 = "BlessedAugust@" fullword ascii wide
        $password98 = "BlessedAUgust@123" fullword ascii wide
        $password99 = "BLESSEDchild@" fullword ascii wide
        $password100 = "BLESSEDyear20" fullword ascii wide
        $password101 = "Blessing123" fullword ascii wide
        $password102 = "Blessings@12345" fullword ascii wide
        $password103 = "BNF!vloc.146" fullword ascii wide
        $password104 = "bobby654" fullword ascii wide
        $password105 = "@bongo1.," fullword ascii wide
        $password106 = "@Bongo1.," fullword ascii wide
        $password107 = "boygirl654321" fullword ascii wide
        $password108 = "bP{dfUwO(S!@" fullword ascii wide
        $password109 = "@Brazil20,," fullword ascii wide
        $password110 = "breakinglimit@" fullword ascii wide
        $password111 = "breakinglimit100%" fullword ascii wide
        $password112 = "bt3tw9wqh#B" fullword ascii wide
        $password113 = "Bukky101@" fullword ascii wide
        $password114 = "+B)Z#Gi1KGK*" fullword ascii wide
        $password115 = "c3l3n@18" fullword ascii wide
        $password116 = "castor123@" fullword ascii wide
        $password117 = "challenge12345" fullword ascii wide
        $password118 = "challenge12345@" fullword ascii wide
        $password119 = "chibuike12345@@@@@" fullword ascii wide
        $password120 = "chibuikelightwork1" fullword ascii wide
        $password121 = "chijiokejackson" fullword ascii wide
        $password122 = ".chimaobi@070" fullword ascii wide
        $password123 = "chimaroke2020" fullword ascii wide
        $password124 = "chinyerewaga2019" fullword ascii wide
        $password125 = "chosen@@@123" fullword ascii wide
        $password126 = "chosen@@@123456" fullword ascii wide
        $password127 = "chuksweeda345" fullword ascii wide
        $password128 = "chukwuma22" fullword ascii wide
        $password129 = "CKnt@CtGcc0" fullword ascii wide
        $password130 = "clark2424@" fullword ascii wide
        $password131 = "#%c,*lVZNIXctE.!BA" fullword ascii wide
        $password132 = "Coded2015" fullword ascii wide
        $password133 = "Co@Iek#)X9" fullword ascii wide
        $password134 = "Comfort@123" fullword ascii wide
        $password135 = "comm1@0321" fullword ascii wide
        $password136 = "computer@147" fullword ascii wide
        $password137 = "conshipping13579" fullword ascii wide
        $password138 = "Control84@" fullword ascii wide
        $password139 = "Conversation2" fullword ascii wide
        $password140 = "cowA$04{lT?u" fullword ascii wide
        $password141 = "cr*fDaW&m@2y6u" fullword ascii wide
        $password142 = "cruizjamesvhjkl@" fullword ascii wide
        $password143 = "%C@sFFb8" fullword ascii wide
        $password144 = "^CuvfABJJ1OM" fullword ascii wide
        $password145 = "cwEqoinR" fullword ascii wide
        $password146 = "cyberindo/cbn205" fullword ascii wide
        $password147 = "Daberechukwuego123" fullword ascii wide
        $password148 = "@damienzy.xyz2240" fullword ascii wide
        $password149 = "dandollars45" fullword ascii wide
        $password150 = "ddhuman@123" fullword ascii wide
        $password151 = "Dedication100%" fullword ascii wide
        $password152 = "dengo@123" fullword ascii wide
        $password153 = "D%gWY^p5" fullword ascii wide
        $password154 = "dho)YOW7" fullword ascii wide
        $password155 = "dhruv_varship5553" fullword ascii wide
        $password156 = "Diaa@Diaa@8" fullword ascii wide
        $password157 = "dj123" fullword ascii wide
        $password158 = "D@kOq4_5tc%n" fullword ascii wide
        $password159 = "dom2424@" fullword ascii wide
        $password160 = "donttouch@00" fullword ascii wide
        $password161 = "D#p!ZC#7" fullword ascii wide
        $password162 = "dragonflam123" fullword ascii wide
        $password163 = "(DS@pOu6" fullword ascii wide
        $password164 = "Dubai@vip123" fullword ascii wide
        $password165 = "Du_v?8Ui%x3p" fullword ascii wide
        $password166 = "Dw1e7Tlo1id" fullword ascii wide
        $password167 = "DwwWTzn3" fullword ascii wide
        $password168 = "@dX2#^%HWdg?fZ;g5n" fullword ascii wide
        $password169 = "eagle*qaz" fullword ascii wide
        $password170 = "eduardojames123" fullword ascii wide
        $password171 = "EEnFWmm9" fullword ascii wide
        $password172 = "efforting@" fullword ascii wide
        $password173 = "^E)GTKL2" fullword ascii wide
        $password174 = "Ehimembano1@" fullword ascii wide
        $password175 = "e$iVNAD7" fullword ascii wide
        $password176 = "eJkG%KP9" fullword ascii wide
        $password177 = "ekuZ4o#9Bj_%" fullword ascii wide
        $password178 = "Emotion1" fullword ascii wide
        $password179 = "enquiry@2020" fullword ascii wide
        $password180 = "enugu042" fullword ascii wide
        $password181 = "@#*eqPS4" fullword ascii wide
        $password182 = "EQQDdWP2" fullword ascii wide
        $password183 = "es_7R59}7bal" fullword ascii wide
        $password184 = "esut96092" fullword ascii wide
        $password185 = "etou01315" fullword ascii wide
        $password186 = "f3nu6R4lH" fullword ascii wide
        $password187 = "faith12AB" fullword ascii wide
        $password188 = "FBZmjprY*6" fullword ascii wide
        $password189 = "F~^fM-8bEkip" fullword ascii wide
        $password190 = "fido2424@" fullword ascii wide
        $password191 = "Figuring@123" fullword ascii wide
        $password192 = "Firas2017!" fullword ascii wide
        $password193 = "FkbjX@(6" fullword ascii wide
        $password194 = "Focus$Pray" fullword ascii wide
        $password195 = "Forexcoinstrade@webmail" fullword ascii wide
        $password196 = "!!!!fororigin" fullword ascii wide
        $password197 = "franckbig123" fullword ascii wide
        $password198 = "fresh826699" fullword ascii wide
        $password199 = "fSnz$T#3" fullword ascii wide
        $password200 = "fySnrmX9" fullword ascii wide
        $password201 = "gcsgaia@1234" fullword ascii wide
        $password202 = "genesis070" fullword ascii wide
        $password203 = "Gera5956" fullword ascii wide
        $password204 = "Germany777@@" fullword ascii wide
        $password205 = "GGASDXZAFCVB65" fullword ascii wide
        $password206 = "GGjVW6,hMG}W" fullword ascii wide
        $password207 = "ginger31" fullword ascii wide
        $password208 = "GL@123456" fullword ascii wide
        $password209 = "glodokplaza15" fullword ascii wide
        $password210 = "GODABEG@" fullword ascii wide
        $password211 = "GodAbegOo#" fullword ascii wide
        $password212 = "GodGrace6665555" fullword ascii wide
        $password213 = "GODhelpme@#" fullword ascii wide
        $password214 = "GODOFSURELOGS123" fullword ascii wide
        $password215 = "GODSGRACE123" fullword ascii wide
        $password216 = "godson00" fullword ascii wide
        $password217 = "GodsPlan@#" fullword ascii wide
        $password218 = "Gomoswa.Purchase123" fullword ascii wide
        $password219 = "goodyear@2020" fullword ascii wide
        $password220 = "Gp:b2Qgqa3*}" fullword ascii wide
        $password221 = "GRACE12345" fullword ascii wide
        $password222 = "greatman32" fullword ascii wide
        $password223 = "GS1Member_4321" fullword ascii wide
        $password224 = "GuG5GK(3m7*Z" fullword ascii wide
        $password225 = "{[g(XaBNF%aJkU*U72" fullword ascii wide
        $password226 = "gyiZHMi6" fullword ascii wide
        $password227 = "[gz6.T*7xLDGn" fullword ascii wide
        $password228 = "Hajarbh@1993" fullword ascii wide
        $password229 = "HaLzYAY8" fullword ascii wide
        $password230 = "@Hammer1980" fullword ascii wide
        $password231 = "HCBo3_tl-nKP" fullword ascii wide
        $password232 = "HelpMELord@#" fullword ascii wide
        $password233 = "HELPmeLORD@" fullword ascii wide
        $password234 = "HeSwjmn6" fullword ascii wide
        $password235 = "HEy2wgSVcS" fullword ascii wide
        $password236 = "(hFuxcD2" fullword ascii wide
        $password237 = "hope2020" fullword ascii wide
        $password238 = "HueCycle" fullword ascii wide
        $password239 = "H*XyvM)5" fullword ascii wide
        $password240 = "HYBRID123@@@" fullword ascii wide
        $password241 = "hygiene@789" fullword ascii wide
        $password242 = "IamFeco$" fullword ascii wide
        $password243 = "@#ie3jej234eWQ" fullword ascii wide
        $password244 = "Ijeomam288" fullword ascii wide
        $password245 = "Ijg2qXIq7^.u" fullword ascii wide
        $password246 = "ikechukwu112" fullword ascii wide
        $password247 = "Ilidza_1322" fullword ascii wide
        $password248 = "Ilovegod12" fullword ascii wide
        $password249 = "Imax170912" fullword ascii wide
        $password250 = "i^*Moaf0" fullword ascii wide
        $password251 = "imzafar75" fullword ascii wide
        $password252 = "In4mation@" fullword ascii wide
        $password253 = "INfinity12345" fullword ascii wide
        $password254 = "INGODWETRUST" fullword ascii wide
        $password255 = "@@Io419090@@" fullword ascii wide
        $password256 = "IpaSkgm5" fullword ascii wide
        $password257 = "I-rec2018@30crest" fullword ascii wide
        $password258 = "ItsTrue@123" fullword ascii wide
        $password259 = "iwuoha241@" fullword ascii wide
        $password260 = "iyke112@@@333" fullword ascii wide
        $password261 = "iyke112@@@444" fullword ascii wide
        $password262 = "%izARl@$-zHKEYwlHM" fullword ascii wide
        $password263 = "j0#c!nNq6iW%" fullword ascii wide
        $password264 = "J3fP8xWq" fullword ascii wide
        $password265 = "J~5v.F5[G06H6}ct{!" fullword ascii wide
        $password266 = "jacksonjogodo" fullword ascii wide
        $password267 = "@jaffinmarknma@344" fullword ascii wide
        $password268 = "JBIdwRx8" fullword ascii wide
        $password269 = "Jeedimetla@55" fullword ascii wide
        $password270 = "J)*(EIv4" fullword ascii wide
        $password271 = "JesusChrist0007" fullword ascii wide
        $password272 = "JesusChrist007" fullword ascii wide
        $password273 = "jiashah123" fullword ascii wide
        $password274 = ")J@i^p#%m4*N" fullword ascii wide
        $password275 = "J%jCb2L=!5~E" fullword ascii wide
        $password276 = "jn&6kG~_w;;A" fullword ascii wide
        $password277 = "Johnpaulifeanyi" fullword ascii wide
        $password278 = "Jqw0iReErt" fullword ascii wide
        $password279 = "*jSBU#f2" fullword ascii wide
        $password280 = "JulyBeGREAT@" fullword ascii wide
        $password281 = "JULYwillBeGOOD@" fullword ascii wide
        $password282 = "kaka1234@1@1" fullword ascii wide
        $password283 = "Kamal@2019" fullword ascii wide
        $password284 = "kBYpSGF1" fullword ascii wide
        $password285 = "kelex2424@" fullword ascii wide
        $password286 = "khalifa2019" fullword ascii wide
        $password287 = "@kingmezz.xyz" fullword ascii wide
        $password288 = "kingqqqqqq1164" fullword ascii wide
        $password289 = "KINGqqqqqq@12" fullword ascii wide
        $password290 = "kings123" fullword ascii wide
        $password291 = "kings@8088" fullword ascii wide
        $password292 = "kingsOFkings9660" fullword ascii wide
        $password293 = "klassic1993" fullword ascii wide
        $password294 = "Kn!EHX%2" fullword ascii wide
        $password295 = "koolestmoney990" fullword ascii wide
        $password296 = "KOSI213141" fullword ascii wide
        $password297 = "kqNbV!Y9" fullword ascii wide
        $password298 = "kR6d.DFet#7w" fullword ascii wide
        $password299 = "k%UJjSH3" fullword ascii wide
        $password300 = "kukeremaster1122" fullword ascii wide
        $password301 = "kvpEP:8:w?z2" fullword ascii wide
        $password302 = "kv(Ymij2" fullword ascii wide
        $password303 = "KyayQQ{Kn$TJ+f;dRd" fullword ascii wide
        $password304 = "#l0v7}}sdfRH" fullword ascii wide
        $password305 = "^l@2~))DQq,z" fullword ascii wide
        $password306 = "L_7do9qu$$eB" fullword ascii wide
        $password307 = "l~}ADs4EsM5;" fullword ascii wide
        $password308 = "{lafa{u^wEx8" fullword ascii wide
        $password309 = "Laiba2001" fullword ascii wide
        $password310 = "LA)R*hh7" fullword ascii wide
        $password311 = "lemper2341" fullword ascii wide
        $password312 = "lFAvm@p#@z92" fullword ascii wide
        $password313 = "LifeDrama@#" fullword ascii wide
        $password314 = "LifeDrama@123" fullword ascii wide
        $password315 = "Lion@4321" fullword ascii wide
        $password316 = "Lioncmgmoney2020" fullword ascii wide
        $password317 = "Lionstep2019" fullword ascii wide
        $password318 = "lj(ZaH!4" fullword ascii wide
        $password319 = "l#mOLGc2" fullword ascii wide
        $password320 = "lochmann2" fullword ascii wide
        $password321 = "$logs2020" fullword ascii wide
        $password322 = "LongJohn@123" fullword ascii wide
        $password323 = "Loverboy123" fullword ascii wide
        $password324 = "Lucas@9842" fullword ascii wide
        $password325 = "marbella1597" fullword ascii wide
        $password326 = "Mariodavid89" fullword ascii wide
        $password327 = "mbatracpm121066" fullword ascii wide
        $password328 = "MEgQ(dB7" fullword ascii wide
        $password329 = "@mexico1.," fullword ascii wide
        $password330 = "@Mexico1.," fullword ascii wide
        $password331 = "@Mexico111." fullword ascii wide
        $password332 = "@Mexico3,." fullword ascii wide
        $password333 = "@mexicod1.," fullword ascii wide
        $password334 = "@mile31.," fullword ascii wide
        $password335 = "Miracle@123.," fullword ascii wide
        $password336 = ".,?!miracleGod12345" fullword ascii wide
        $password337 = "MKNXoqR2" fullword ascii wide
        $password338 = "mkoify147@" fullword ascii wide
        $password339 = "$MKXG2eN$]mXD" fullword ascii wide
        $password340 = "MmE$R)c1" fullword ascii wide
        $password341 = "Mmhh#2014" fullword ascii wide
        $password342 = "mMtRZHe4" fullword ascii wide
        $password343 = "moin@26919" fullword ascii wide
        $password344 = "moneyguy76" fullword ascii wide
        $password345 = "moneymustdrop" fullword ascii wide
        $password346 = "Montanemumbai*@*@*@321" fullword ascii wide
        $password347 = "MoreGrace@#" fullword ascii wide
        $password348 = "MOREMONEY123" fullword ascii wide
        $password349 = "MOVxGKLe2" fullword ascii wide
        $password350 = "mrshelp23409@!!#" fullword ascii wide
        $password351 = "mumbai@333" fullword ascii wide
        $password352 = "MumCon05" fullword ascii wide
        $password353 = "Mummy212" fullword ascii wide
        $password354 = "muriithi2018" fullword ascii wide
        $password355 = "myhp6000" fullword ascii wide
        $password356 = "naci@123" fullword ascii wide
        $password357 = "NAEgz9DX" fullword ascii wide
        $password358 = "#nD}b?rwP7i4" fullword ascii wide
        $password359 = "NeverGiveUp@123" fullword ascii wide
        $password360 = "NewAugust1303@" fullword ascii wide
        $password361 = "NewBlessings" fullword ascii wide
        $password362 = "NewBlessings@" fullword ascii wide
        $password363 = "Newest@1234#" fullword ascii wide
        $password364 = "NewFlames@123" fullword ascii wide
        $password365 = "newpassword216" fullword ascii wide
        $password366 = "NEWways@" fullword ascii wide
        $password367 = "Newwealth2020@" fullword ascii wide
        $password368 = "ng3:I!*6zPve" fullword ascii wide
        $password369 = "n,gmAXEv+C*Q" fullword ascii wide
        $password370 = "Nigels1975!" fullword ascii wide
        $password371 = "nnedimma080" fullword ascii wide
        $password372 = "noicamrofni15" fullword ascii wide
        $password373 = "NoisyGeneration#" fullword ascii wide
        $password374 = "Nolies99" fullword ascii wide
        //$password375 = "None" fullword ascii wide
        $password376 = "%nPEwL.AuzFn3" fullword ascii wide
        $password377 = ")^nveCU9" fullword ascii wide
        $password378 = "nwaotu65" fullword ascii wide
        $password379 = "@nxtlevel.xyz2" fullword ascii wide
        $password380 = "O1212@3213#" fullword ascii wide
        $password381 = "+O5vY$hklw8:" fullword ascii wide
        $password382 = "Obaten10" fullword ascii wide
        $password383 = "Occupation123$" fullword ascii wide
        $password384 = "odenigbo090" fullword ascii wide
        $password385 = "OGOM12345" fullword ascii wide
        $password386 = "OhMyGod#357" fullword ascii wide
        $password387 = "Olaola123@" fullword ascii wide
        $password388 = "olivia@8000" fullword ascii wide
        $password389 = "oluwarugged99" fullword ascii wide
        $password390 = "Omer24862486" fullword ascii wide
        $password391 = "OmsrisairamIW$6" fullword ascii wide
        $password392 = "OneDay@time" fullword ascii wide
        $password393 = "onegod5050()" fullword ascii wide
        $password394 = "Onyeoba111" fullword ascii wide
        $password395 = "^{Opb6h,rjW^" fullword ascii wide
        $password396 = "oppo@12345" fullword ascii wide
        $password397 = "Orders@1234" fullword ascii wide
        $password398 = "^orfepu5" fullword ascii wide
        $password399 = "originaloriginal" fullword ascii wide
        $password400 = "OTelvie1234" fullword ascii wide
        $password401 = "O-xgNxpHw~?h5H.ZEB" fullword ascii wide
        $password402 = "o^Z0CIU?^yL2" fullword ascii wide
        $password403 = "Pass@#2019" fullword ascii wide
        $password404 = "pAsSword@#1" fullword ascii wide
        $password405 = "payment1759" fullword ascii wide
        $password406 = "pb#oiDu3" fullword ascii wide
        $password407 = "peru2016" fullword ascii wide
        $password408 = "philomina1234567890" fullword ascii wide
        $password409 = "pi.cOF{td__m" fullword ascii wide
        $password410 = "=piYR_r.%[Ch" fullword ascii wide
        $password411 = "Playboy@11" fullword ascii wide
        $password412 = "PLAYBOY@123" fullword ascii wide
        $password413 = "Pl@nedon1234" fullword ascii wide
        $password414 = "Pnk*3lR8{~up" fullword ascii wide
        $password415 = "pointaz45" fullword ascii wide
        $password416 = "PoolExc129" fullword ascii wide
        $password417 = "pounds123\"\"@@" fullword ascii wide
        $password418 = "Power@123" fullword ascii wide
        $password419 = "PQ^vN@^wm6" fullword ascii wide
        $password420 = "pr0duct10n" fullword ascii wide
        $password421 = "Prashant@123" fullword ascii wide
        $password422 = "prashant@92" fullword ascii wide
        $password423 = "primos16sofa" fullword ascii wide
        $password424 = "pro7122" fullword ascii wide
        $password425 = "Proizvodnja2018" fullword ascii wide
        $password426 = "prosperity1" fullword ascii wide
        $password427 = "Protected@123" fullword ascii wide
        $password428 = "P@ssw0rd" fullword ascii wide
        $password429 = "pZQhjl!9" fullword ascii wide
        $password430 = "Q9sJP$***Mih53!" fullword ascii wide
        $password431 = "qee!HYCH4" fullword ascii wide
        $password432 = "#qeQ*y!9" fullword ascii wide
        $password433 = "QJLs)ui3" fullword ascii wide
        $password434 = "QMvStW^7" fullword ascii wide
        $password435 = "Qo!:ozhL}80k" fullword ascii wide
        $password436 = "qqkgpIN2" fullword ascii wide
        $password437 = "qwerty123@" fullword ascii wide
        $password438 = "qwerty123@@" fullword ascii wide
        $password439 = "qwerty123@@@" fullword ascii wide
        $password440 = "qwerty1234" fullword ascii wide
        $password441 = "@qwerty12345" fullword ascii wide
        $password442 = "qwerty12345" fullword ascii wide
        $password443 = "qwerty123456" fullword ascii wide
        $password444 = "Qwerty2214" fullword ascii wide
        $password445 = "QWErty654321" fullword ascii wide
        $password446 = "qwertyuiop[]\\" fullword ascii wide
        $password447 = "Qwertyuiop@12" fullword ascii wide
        $password448 = "qzf5:Ee~1hI?" fullword ascii wide
        $password449 = "r1NmBO4h" fullword ascii wide
        $password450 = "R[2](NaueJp!6tL?sW" fullword ascii wide
        $password451 = "r35@Q~hgw_Pc" fullword ascii wide
        $password452 = "#r4j#citeureup#13" fullword ascii wide
        $password453 = "r4tn41226" fullword ascii wide
        $password454 = "rabbO@2@70" fullword ascii wide
        $password455 = "@Ranger1.," fullword ascii wide
        $password456 = "rBY;gGiXQk?l" fullword ascii wide
        $password457 = "rDdlJ%h9" fullword ascii wide
        //$password458 = "REDACTED" fullword ascii wide
        $password459 = "redwing39613613**123#" fullword ascii wide
        $password460 = "Regina2020@" fullword ascii wide
        $password461 = "Remember@123" fullword ascii wide
        $password462 = "Remember@123#" fullword ascii wide
        $password463 = "requestShow@" fullword ascii wide
        $password464 = "Res@123" fullword ascii wide
        $password465 = "!^RH#ei2" fullword ascii wide
        $password466 = "Riazeda@321" fullword ascii wide
        $password467 = "router11477" fullword ascii wide
        $password468 = "Royal@2019" fullword ascii wide
        $password469 = "rqa4@slpl" fullword ascii wide
        $password470 = "r}R6s@[7,k$j" fullword ascii wide
        $password471 = "ryan10000@" fullword ascii wide
        $password472 = "rYLGz!p8" fullword ascii wide
        $password473 = "}$S0V}hWvngO" fullword ascii wide
        $password474 = "sages101" fullword ascii wide
        $password475 = "Sages101*" fullword ascii wide
        $password476 = "Sahara*542" fullword ascii wide
        $password477 = "Salesteam@PRO" fullword ascii wide
        $password478 = "Sa#Ma@78-6" fullword ascii wide
        $password479 = "sardunya?135" fullword ascii wide
        $password480 = "sazzad@pal#" fullword ascii wide
        $password481 = "*sBbUQf9B9$.f" fullword ascii wide
        $password482 = "schenker@okani123" fullword ascii wide
        $password483 = "schenkerokani123" fullword ascii wide
        $password484 = "SeaBeach2060$" fullword ascii wide
        $password485 = "sender@#1235" fullword ascii wide
        $password486 = "sepp2424@" fullword ascii wide
        $password487 = "SeptemberBlessings@" fullword ascii wide
        $password488 = "server1123455" fullword ascii wide
        $password489 = "server1543211" fullword ascii wide
        $password490 = "^sFO^Hb0" fullword ascii wide
        $password491 = "shyam*1411" fullword ascii wide
        $password492 = "SIALKOT12345" fullword ascii wide
        $password493 = "sih70111" fullword ascii wide
        $password494 = "Silence1234@" fullword ascii wide
        $password495 = "SIMON3x0t1c!" fullword ascii wide
        $password496 = "@Sleeves100" fullword ascii wide
        $password497 = "(SLYNY(3" fullword ascii wide
        $password498 = "smith@222" fullword ascii wide
        $password499 = "Sobrero122++@" fullword ascii wide
        $password500 = "sOeKk#E6" fullword ascii wide
        $password501 = "somc2424@" fullword ascii wide
        $password502 = "Someone1234" fullword ascii wide
        $password503 = "SometimesINLIFE@" fullword ascii wide
        $password504 = "Sony786786@" fullword ascii wide
        $password505 = "Spie#th2017" fullword ascii wide
        $password506 = "~@Sp$wQecPDi***" fullword ascii wide
        $password507 = "STAYSAFE123" fullword ascii wide
        $password508 = "Stencil1@" fullword ascii wide
        $password509 = "Success0803959" fullword ascii wide
        $password510 = "success2016" fullword ascii wide
        $password511 = "success2020" fullword ascii wide
        $password512 = "success2020@" fullword ascii wide
        $password513 = "@Success$2020" fullword ascii wide
        $password514 = "successman12" fullword ascii wide
        $password515 = "sujit@41#" fullword ascii wide
        $password516 = "Sunday1983@" fullword ascii wide
        $password517 = "SURELOGS123" fullword ascii wide
        $password518 = "$^s@WL^v4" fullword ascii wide
        $password519 = "SxEUHno3" fullword ascii wide
        $password520 = "-szG^tj_nEpo" fullword ascii wide
        $password521 = "t4nuJko1" fullword ascii wide
        $password522 = "t%[D2FmSeQezu,}e" fullword ascii wide
        $password523 = "!td!$yHM4DMKS" fullword ascii wide
        //$password524 = "test" fullword ascii wide
        $password525 = "TESTIMONY@123" fullword ascii wide
        $password526 = "TgZG^uM1" fullword ascii wide
        $password527 = "theoldlady" fullword ascii wide
        $password528 = "Theunis@123" fullword ascii wide
        $password529 = "TJUFleSf@4xH" fullword ascii wide
        $password530 = "tnbJ_YL&GmP}" fullword ascii wide
        $password531 = "Tomorrow@1234#" fullword ascii wide
        $password532 = "tonero4417" fullword ascii wide
        $password533 = "tooblessed77" fullword ascii wide
        $password534 = "Tr4nsm3r2019" fullword ascii wide
        $password535 = "Try1234567@.," fullword ascii wide
        $password536 = "TryAgain@123" fullword ascii wide
        $password537 = "Tt600402920" fullword ascii wide
        $password538 = "ttE7Ux7*am%@" fullword ascii wide
        $password539 = "tvyTkyG1" fullword ascii wide
        $password540 = "TYfAhNp0" fullword ascii wide
        $password541 = ")t@zbxV0" fullword ascii wide
        $password542 = "TzWtKO@0" fullword ascii wide
        $password543 = "]U~8KK=B.MD+" fullword ascii wide
        $password544 = "ubrxsf" fullword ascii wide
        $password545 = "uchenna@&1992" fullword ascii wide
        $password546 = "udug2424@" fullword ascii wide
        $password547 = "Ujdd9782@d" fullword ascii wide
        $password548 = "Uj!pBcl1" fullword ascii wide
        $password549 = "UkFAx(W9" fullword ascii wide
        $password550 = "uLoxciundbXokAWJ" fullword ascii wide
        $password551 = "uLrOsjJYN9" fullword ascii wide
        $password552 = "UmX3iJQg" fullword ascii wide
        $password553 = "unisoln@2017" fullword ascii wide
        $password554 = "=uNm5^6#!,6," fullword ascii wide
        $password555 = "user@12345" fullword ascii wide
        $password556 = "uUM%FTV4" fullword ascii wide
        $password557 = "UYE(@@HDS" fullword ascii wide
        $password558 = "VISION2020" fullword ascii wide
        $password559 = "vJ%}D$h%kJgI" fullword ascii wide
        $password560 = "Vn,?+Es5;dNayEvk]*" fullword ascii wide
        $password561 = "voveLzS0" fullword ascii wide
        $password562 = "v~t-0~GGykudc@r&u*" fullword ascii wide
        $password563 = "#VtBmodc!0" fullword ascii wide
        $password564 = "vU}t$13*orkO" fullword ascii wide
        $password565 = "W5@UcJC_{Y0G" fullword ascii wide
        $password566 = "wale2424@" fullword ascii wide
        $password567 = "wassodedon22" fullword ascii wide
        $password568 = "WBpJYRW0" fullword ascii wide
        $password569 = "@wealth$2020" fullword ascii wide
        $password570 = "Welcome01" fullword ascii wide
        $password571 = "Welcome@123" fullword ascii wide
        $password572 = "Wenenighty.," fullword ascii wide
        $password573 = "wf@(%JY9" fullword ascii wide
        $password574 = "whywori#@#" fullword ascii wide
        $password575 = "whyworry.," fullword ascii wide
        $password576 = "Whyworry#@" fullword ascii wide
        $password577 = "WHYworry??#" fullword ascii wide
        $password578 = "whyworry01#" fullword ascii wide
        $password579 = "whyworry1090#" fullword ascii wide
        $password580 = "whyworry10902020" fullword ascii wide
        $password581 = "whyworry@123" fullword ascii wide
        $password582 = "whyworry123@" fullword ascii wide
        $password583 = "Whyworry90#" fullword ascii wide
        $password584 = "@willsmith1.," fullword ascii wide
        $password585 = "winnerq123" fullword ascii wide
        $password586 = "Wm8XHLc4" fullword ascii wide
        $password587 = "WNFpR3FOMJ@6" fullword ascii wide
        $password588 = "WORK@2016" fullword ascii wide
        $password589 = "WORK@2020" fullword ascii wide
        $password590 = "wRwswHW2" fullword ascii wide
        $password591 = "wURFDkR4" fullword ascii wide
        $password592 = "w:Vo?o5q9*pU" fullword ascii wide
        $password593 = "wz(rDXZ9" fullword ascii wide
        $password594 = "X3Sg3$?fl?ro" fullword ascii wide
        $password595 = "X5=KN(JJIXso" fullword ascii wide
        $password596 = "xGrj9Nv~*8@c" fullword ascii wide
        $password597 = "xIacrSQ0" fullword ascii wide
        $password598 = "x(jhBsE7" fullword ascii wide
        $password599 = "XNQdOIy4" fullword ascii wide
        $password600 = "y8wG[wgBvT]F" fullword ascii wide
        $password601 = "YakiGate669012" fullword ascii wide
        $password602 = "YEK7Ne@.6,m]vBXKQw" fullword ascii wide
        $password603 = "ygsus2020" fullword ascii wide
        $password604 = "YihCWmz1" fullword ascii wide
        $password605 = "Y!jMTYo4" fullword ascii wide
        $password606 = "yngt90215" fullword ascii wide
        $password607 = "YNvjQ*3rRrr+***" fullword ascii wide
        $password608 = "y^PAbwW4" fullword ascii wide
        $password609 = "zainab123" fullword ascii wide
        $password610 = "zbfonah4" fullword ascii wide
        $password611 = "zlPGlvr9" fullword ascii wide
        $password612 = "znL#cNm1" fullword ascii wide
        $password613 = "{Zo3Dn4H#3G)" fullword ascii wide
        $password614 = "zra1@!G8gQ+i" fullword ascii wide
        $password615 = "zrUqmpL75877" fullword ascii wide
        $password616 = "^$~zvG4Vzg7Q" fullword ascii wide
        $password617 = "zYLduQa6" fullword ascii wide
        $password618 = "Zz1313!ng" fullword ascii wide
        $password619 = "$^z*ZWc2" fullword ascii wide
    condition:
        any of them
}