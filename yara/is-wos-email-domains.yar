rule ISWOS_Indicator_Email_Domain {
    meta:
        author = "ditekshen"
        description = "Domains from the accounts used in SMTP(S) exfiltration and not the queried domain"
        source = "https://github.com/ditekshen/is-wos"
        revision = "20200815"
        fp = "low"
    strings:
        $domain1 = "@1st-ship.com" ascii wide nocase
        $domain2 = "@3enaluminyum.com.tr" ascii wide nocase
        $domain3 = "@abarsiava.com" ascii wide nocase
        $domain4 = "@abiste.biz" ascii wide nocase
        $domain5 = "@abuodahbros.com" ascii wide nocase
        $domain6 = "@abuodehbros.co" ascii wide nocase
        $domain7 = "@acmecarp.com" ascii wide nocase
        $domain8 = "@acroative.com" ascii wide nocase
        $domain9 = "@activepumps.com" ascii wide nocase
        $domain10 = "@ada.org.do" ascii wide nocase
        $domain11 = "@adenerqyeurope.co.uk" ascii wide nocase
        $domain12 = "@adityaprinters.com" ascii wide nocase
        $domain13 = "@advoicemediaworks.com" ascii wide nocase
        $domain14 = "@aero-cabln.com" ascii wide nocase
        $domain15 = "@aerotacctvn.com" ascii wide nocase
        $domain16 = "@afinoxdesign.com" ascii wide nocase
        $domain17 = "@agavecomquista.com" ascii wide nocase
        $domain18 = "@agifreiqht.com" ascii wide nocase
        $domain19 = "@agpmeats.com" ascii wide nocase
        $domain20 = "@agri-chernicals.net" ascii wide nocase
        $domain21 = "@airuhomes.com" ascii wide nocase
        $domain22 = "@akonuchenwam.org" ascii wide nocase
        $domain23 = "@albaniandailynews.com" ascii wide nocase
        $domain24 = "@alfanoos.com.sa" ascii wide nocase
        $domain25 = "@allaceautoparts.me" ascii wide nocase
        $domain26 = "@alliadintl.com" ascii wide nocase
        $domain27 = "@alltoplighting.icu" ascii wide nocase
        $domain28 = "@almushrefcoop.com" ascii wide nocase
        $domain29 = "@altrii.com" ascii wide nocase
        $domain30 = "@alvadiwipa.com" ascii wide nocase
        $domain31 = "@amazirgind.com" ascii wide nocase
        $domain32 = "@ambreh.com" ascii wide nocase
        $domain33 = "@americantrevalerinc.com" ascii wide nocase
        $domain34 = "@ametexegypts.info" ascii wide nocase
        $domain35 = "@amethishipping.com" ascii wide nocase
        $domain36 = "@ametropolis.com" ascii wide nocase
        $domain37 = "@amexworldwide.com" ascii wide nocase
        $domain38 = "@amisglobaltransport.com" ascii wide nocase
        $domain39 = "@ampail.com" ascii wide nocase
        $domain40 = "@anding-tw.com" ascii wide nocase
        $domain41 = "@antolini.tk" ascii wide nocase
        $domain42 = "@aptraining.biz" ascii wide nocase
        $domain43 = "@arabianwebdesigner.com" ascii wide nocase
        $domain44 = "@arrmet.in" ascii wide nocase
        $domain45 = "@artiinox.com" ascii wide nocase
        $domain46 = "@askon.co.id" ascii wide nocase
        $domain47 = "@asplparts.com" ascii wide nocase
        $domain48 = "@assocham.icu" ascii wide nocase
        $domain49 = "@axolta.com" ascii wide nocase
        $domain50 = "@aydangroup.com.my" ascii wide nocase
        $domain51 = "@bandaichemical.com" ascii wide nocase
        $domain52 = "@baplhvac-uk.com" ascii wide nocase
        $domain53 = "@barclarysbank-uk.com" ascii wide nocase
        $domain54 = "@bazciproduct.com" ascii wide nocase
        $domain55 = "@bconductt.icu" ascii wide nocase
        $domain56 = "@bellfilght.com" ascii wide nocase
        $domain57 = "@besco.com.sa" ascii wide nocase
        $domain58 = "@bestinjectionmachines.com" ascii wide nocase
        $domain59 = "@bethfels.org" ascii wide nocase
        $domain60 = "@bhavnatutor.com" ascii wide nocase
        $domain61 = "@bigmanstan.com" ascii wide nocase
        $domain62 = "@biilt.me" ascii wide nocase
        $domain63 = "@bikossoft.me" ascii wide nocase
        $domain64 = "@biznetvigat0r.com" ascii wide nocase
        $domain65 = "@blacksea.red" ascii wide nocase
        $domain66 = "@blessedinc.xyz" ascii wide nocase
        $domain67 = "@blowtac-tw.com" ascii wide nocase
        $domain68 = "@bluesial.com" ascii wide nocase
        $domain69 = "@bmssrevis.com" ascii wide nocase
        $domain70 = "@bnb-spa.com" ascii wide nocase
        $domain71 = "@bnfurniture.net" ascii wide nocase
        $domain72 = "@bodycarecreations.com" ascii wide nocase
        $domain73 = "@bristol-fire.co" ascii wide nocase
        $domain74 = "@btconrnect.com" ascii wide nocase
        $domain75 = "@burststreamwq1.website" ascii wide nocase
        $domain76 = "@cairoways.icu" ascii wide nocase
        $domain77 = "@cairoways.me" ascii wide nocase
        $domain78 = "@canvanatransport.com" ascii wide nocase
        $domain79 = "@cargoair.bg" ascii wide nocase
        $domain80 = "@cbn.net.id" ascii wide nocase
        $domain81 = "@chemshire.org" ascii wide nocase
        $domain82 = "@chinacables.icu" ascii wide nocase
        $domain83 = "@chucksmode.us" ascii wide nocase
        $domain84 = "@cinco.icu" ascii wide nocase
        $domain85 = "@citotest.co" ascii wide nocase
        $domain86 = "@cjcurrent.com" ascii wide nocase
        $domain87 = "@climasenmonterrey.com.mx" ascii wide nocase
        $domain88 = "@coducation.com.my" ascii wide nocase
        $domain89 = "@cognitioperu.com" ascii wide nocase
        $domain90 = "@comero.us" ascii wide nocase
        $domain91 = "@comfortkids.in" ascii wide nocase
        $domain92 = "@comsats.net.pk" ascii wide nocase
        $domain93 = "@connectus-trade.net" ascii wide nocase
        $domain94 = "@conshipping.ro" ascii wide nocase
        $domain95 = "@contecs-e.com" ascii wide nocase
        $domain96 = "@continentalmanpower.com" ascii wide nocase
        $domain97 = "@copyrap.com" ascii wide nocase
        $domain98 = "@corinox.com.tr" ascii wide nocase
        $domain99 = "@cosea.mx" ascii wide nocase
        $domain100 = "@cpmindia.co.in" ascii wide nocase
        $domain101 = "@crawfordjamaica.com" ascii wide nocase
        $domain102 = "@creacionesjlyr.com" ascii wide nocase
        $domain103 = "@crestpak.com" ascii wide nocase
        $domain104 = "@criiteo.com" ascii wide nocase
        $domain105 = "@cronimet.me" ascii wide nocase
        $domain106 = "@cropchemicals.co.in" ascii wide nocase
        $domain107 = "@crowncontainerbd.icu" ascii wide nocase
        $domain108 = "@crowncorke.com" ascii wide nocase
        $domain109 = "@csatolin.com" ascii wide nocase
        $domain110 = "@dachanq.cc" ascii wide nocase
        $domain111 = "@dadatiles.com.au" ascii wide nocase
        $domain112 = "@daiphatfood.com.vn" ascii wide nocase
        $domain113 = "@damienzy.xyz" ascii wide nocase
        $domain114 = "@damllakimya.com" ascii wide nocase
        $domain115 = "@dandopub.mu" ascii wide nocase
        $domain116 = "@ddimnepal.com" ascii wide nocase
        $domain117 = "@deepblueamerica.com" ascii wide nocase
        $domain118 = "@deepsaeemirates.com" ascii wide nocase
        $domain119 = "@dehydratedoniongarlic.com" ascii wide nocase
        $domain120 = "@desmaindian.com" ascii wide nocase
        $domain121 = "@dgrrfy.com" ascii wide nocase
        $domain122 = "@djindustries.net" ascii wide nocase
        $domain123 = "@dongaseimcon.com" ascii wide nocase
        $domain124 = "@dormakeba.com" ascii wide nocase
        $domain125 = "@drngetu.co.za" ascii wide nocase
        $domain126 = "@dssadis.com" ascii wide nocase
        $domain127 = "@dstec.mx" ascii wide nocase
        $domain128 = "@dubhe-kr.icu" ascii wide nocase
        $domain129 = "@dutchlogs.us" ascii wide nocase
        $domain130 = "@dutchworld.space" ascii wide nocase
        $domain131 = "@dwdl.com.bd" ascii wide nocase
        $domain132 = "@eagleeyeapparels.com" ascii wide nocase
        $domain133 = "@eastendfood-uk.icu" ascii wide nocase
        $domain134 = "@eco-mania.es" ascii wide nocase
        $domain135 = "@ecoorganic.co" ascii wide nocase
        $domain136 = "@edifler.xyz" ascii wide nocase
        $domain137 = "@efx.net.nz" ascii wide nocase
        $domain138 = "@eimarwafoods.com" ascii wide nocase
        $domain139 = "@ejazontheweb.com" ascii wide nocase
        $domain140 = "@eloelokendi.com" ascii wide nocase
        $domain141 = "@elsemillero.org.bo" ascii wide nocase
        $domain142 = "@emaillogs.top" ascii wide nocase
        $domain143 = "@emeco.icu" ascii wide nocase
        $domain144 = "@emmannar.com" ascii wide nocase
        $domain145 = "@empromae.com" ascii wide nocase
        $domain146 = "@emss.us" ascii wide nocase
        $domain147 = "@energistx.com" ascii wide nocase
        $domain148 = "@enmark.com.my" ascii wide nocase
        $domain149 = "@eriiell.com" ascii wide nocase
        $domain150 = "@espiralrelojoaria.com" ascii wide nocase
        $domain151 = "@estimx.club" ascii wide nocase
        $domain152 = "@euramtec.pw" ascii wide nocase
        $domain153 = "@eurocell.us" ascii wide nocase
        $domain154 = "@evapimpcoltd.pw" ascii wide nocase
        $domain155 = "@excelarifreight.com" ascii wide nocase
        $domain156 = "@excellent.ba" ascii wide nocase
        $domain157 = "@exoticpools.com.au" ascii wide nocase
        $domain158 = "@exploits.site" ascii wide nocase
        $domain159 = "@fakly-cambodia.com" ascii wide nocase
        $domain160 = "@faltelecom.com" ascii wide nocase
        $domain161 = "@farm-com.me" ascii wide nocase
        $domain162 = "@fendaleltd.com" ascii wide nocase
        $domain163 = "@fernsturm.com" ascii wide nocase
        $domain164 = "@filelog.info" ascii wide nocase
        $domain165 = "@firstgradecourier.com" ascii wide nocase
        $domain166 = "@fiscalitate.eu" ascii wide nocase
        $domain167 = "@flood-protection.org" ascii wide nocase
        $domain168 = "@flsrnidth.com" ascii wide nocase
        $domain169 = "@flyegyptaviation.com" ascii wide nocase
        $domain170 = "@flyxpo.com" ascii wide nocase
        $domain171 = "@forexcoinstrade.com" ascii wide nocase
        $domain172 = "@fox-it.me" ascii wide nocase
        $domain173 = "@friendships-ke.icu" ascii wide nocase
        $domain174 = "@frohnn.com" ascii wide nocase
        $domain175 = "@galaxypharma-co-ke.pw" ascii wide nocase
        $domain176 = "@gammavilla.org" ascii wide nocase
        $domain177 = "@garnishmaster.com" ascii wide nocase
        $domain178 = "@gcco.dz" ascii wide nocase
        $domain179 = "@gcs.co.in" ascii wide nocase
        $domain180 = "@ge-lndustry.com" ascii wide nocase
        $domain181 = "@generce.com" ascii wide nocase
        $domain182 = "@gfaqrochem.com" ascii wide nocase
        $domain183 = "@gheytarencarpet.com" ascii wide nocase
        $domain184 = "@giivin.com" ascii wide nocase
        $domain185 = "@gitggn.com" ascii wide nocase
        $domain186 = "@gl0beactiveltd.com" ascii wide nocase
        $domain187 = "@glovadus.com" ascii wide nocase
        $domain188 = "@goldenfance.com" ascii wide nocase
        $domain189 = "@gomoswa.com" ascii wide nocase
        $domain190 = "@goodland.com.vn" ascii wide nocase
        $domain191 = "@gopaldasvisram.com" ascii wide nocase
        $domain192 = "@gpgolbal.com" ascii wide nocase
        $domain193 = "@graduate.org" ascii wide nocase
        $domain194 = "@groupoinkafoods.com" ascii wide nocase
        $domain195 = "@gruppodigitouch.me" ascii wide nocase
        $domain196 = "@gs1id.org" ascii wide nocase
        $domain197 = "@gtbenk-plc.com" ascii wide nocase
        $domain198 = "@gtelecable.com" ascii wide nocase
        $domain199 = "@gtp-us.com" ascii wide nocase
        $domain200 = "@guddupak.com" ascii wide nocase
        $domain201 = "@guiarapidopublicidade.com.br" ascii wide nocase
        $domain202 = "@hajartrading.net" ascii wide nocase
        $domain203 = "@hanwiha.com" ascii wide nocase
        $domain204 = "@haveusearotech.com" ascii wide nocase
        $domain205 = "@hdtrans.me" ascii wide nocase
        $domain206 = "@highestgame.us" ascii wide nocase
        $domain207 = "@hilmarcheeze.com" ascii wide nocase
        $domain208 = "@hitechnocrats.com" ascii wide nocase
        $domain209 = "@hive-decor.com" ascii wide nocase
        $domain210 = "@holdlngredlich.com" ascii wide nocase
        $domain211 = "@hotelblu.es" ascii wide nocase
        $domain212 = "@hotelmadridtorrevieja.com" ascii wide nocase
        $domain213 = "@hraspirations.com" ascii wide nocase
        $domain214 = "@hsisteels.com" ascii wide nocase
        $domain215 = "@huatengaccessfloor.icu" ascii wide nocase
        $domain216 = "@hustle360.a2hosted.com" ascii wide nocase
        $domain217 = "@ibc.by" ascii wide nocase
        $domain218 = "@ieflowmeters.com" ascii wide nocase
        $domain219 = "@igihm.icu" ascii wide nocase
        $domain220 = "@ike2020.xyz" ascii wide nocase
        $domain221 = "@ilclaw.com.ph" ascii wide nocase
        $domain222 = "@ilserreno.com" ascii wide nocase
        $domain223 = "@innovecera.com" ascii wide nocase
        $domain224 = "@inoksan-tr.com" ascii wide nocase
        $domain225 = "@inpark.rs" ascii wide nocase
        $domain226 = "@insooryaexpresscargo.com" ascii wide nocase
        $domain227 = "@intarscan.org" ascii wide nocase
        $domain228 = "@interexpress.us" ascii wide nocase
        $domain229 = "@inventweld.com" ascii wide nocase
        $domain230 = "@ironhandco.com" ascii wide nocase
        $domain231 = "@iskreameco.com" ascii wide nocase
        $domain232 = "@islandkingpools.com" ascii wide nocase
        $domain233 = "@ite-gr.com" ascii wide nocase
        $domain234 = "@jaccontracting.com" ascii wide nocase
        $domain235 = "@jakartta.xyz" ascii wide nocase
        $domain236 = "@jandregon.com" ascii wide nocase
        $domain237 = "@jdc.net.in" ascii wide nocase
        $domain238 = "@jia-ilda.com" ascii wide nocase
        $domain239 = "@jiqdyi.com" ascii wide nocase
        $domain240 = "@jiratane.com" ascii wide nocase
        $domain241 = "@jkamani.xyz" ascii wide nocase
        $domain242 = "@jpah.org" ascii wide nocase
        $domain243 = "@jpme.org.in" ascii wide nocase
        $domain244 = "@juili-tw.com" ascii wide nocase
        $domain245 = "@kagabo.net" ascii wide nocase
        $domain246 = "@kassohome.com.tr" ascii wide nocase
        $domain247 = "@kccambodia.com" ascii wide nocase
        $domain248 = "@kennycorping.com" ascii wide nocase
        $domain249 = "@kingmezz.xyz" ascii wide nocase
        $domain250 = "@kingzmez.xyz" ascii wide nocase
        $domain251 = "@koohejisafety.com" ascii wide nocase
        $domain252 = "@kordelos-gr.co" ascii wide nocase
        $domain253 = "@koreamail.com" ascii wide nocase
        $domain254 = "@kteadubai.com" ascii wide nocase
        $domain255 = "@larbaxpo.com" ascii wide nocase
        $domain256 = "@latrivenetecavi.com" ascii wide nocase
        $domain257 = "@leaderart-my.com" ascii wide nocase
        $domain258 = "@le-belt.co.za" ascii wide nocase
        $domain259 = "@legalcounselbd.com" ascii wide nocase
        $domain260 = "@leltbank.com" ascii wide nocase
        $domain261 = "@lepta.website" ascii wide nocase
        $domain262 = "@lidyatriko-com.me" ascii wide nocase
        $domain263 = "@lionsar.lv" ascii wide nocase
        $domain264 = "@list.ru" ascii wide nocase
        $domain265 = "@ljves.com" ascii wide nocase
        $domain266 = "@log70.com" ascii wide nocase
        $domain267 = "@logsresultbox.xyz" ascii wide nocase
        $domain268 = "@luckyshippinq.com" ascii wide nocase
        $domain269 = "@lysaghtgroup.com" ascii wide nocase
        $domain270 = "@maccinox.com" ascii wide nocase
        $domain271 = "@maizinternational.com" ascii wide nocase
        $domain272 = "@manex-ist.cf" ascii wide nocase
        $domain273 = "@mangero.xyz" ascii wide nocase
        $domain274 = "@manunggalkaroseri.com" ascii wide nocase
        $domain275 = "@marejgroup.com" ascii wide nocase
        $domain276 = "@marmarisferry.com" ascii wide nocase
        $domain277 = "@masterindo.net" ascii wide nocase
        $domain278 = "@mechatron-gmbh.ga" ascii wide nocase
        $domain279 = "@medicproduction.gq" ascii wide nocase
        $domain280 = "@mediurge.com" ascii wide nocase
        $domain281 = "@medoermw.org" ascii wide nocase
        $domain282 = "@mercananaokulu.com" ascii wide nocase
        $domain283 = "@merrsen.com" ascii wide nocase
        $domain284 = "@metalfabme.icu" ascii wide nocase
        $domain285 = "@metalfabne.com" ascii wide nocase
        $domain286 = "@microhaem-ug.co" ascii wide nocase
        $domain287 = "@miketony-tw.com" ascii wide nocase
        $domain288 = "@mindroy.com" ascii wide nocase
        $domain289 = "@momrol.com" ascii wide nocase
        $domain290 = "@mondastudio.com" ascii wide nocase
        $domain291 = "@montacargasperu.com" ascii wide nocase
        $domain292 = "@montana.co.ke" ascii wide nocase
        $domain293 = "@montaneshipping.com" ascii wide nocase
        $domain294 = "@mygoldenaegle.com" ascii wide nocase
        $domain295 = "@mzrnbd.com" ascii wide nocase
        $domain296 = "@na-superhrd.com" ascii wide nocase
        $domain297 = "@nationalportservices.cam" ascii wide nocase
        $domain298 = "@nedtek.com.au" ascii wide nocase
        $domain299 = "@netalkar.co.in" ascii wide nocase
        $domain300 = "@nokachi.rs" ascii wide nocase
        $domain301 = "@novaa-ship.com" ascii wide nocase
        $domain302 = "@nsmelectronics.com" ascii wide nocase
        $domain303 = "@nxtlevel.xyz" ascii wide nocase
        $domain304 = "@oilexindia.com" ascii wide nocase
        $domain305 = "@okgrocer.co.za" ascii wide nocase
        $domain306 = "@omibearing.com" ascii wide nocase
        $domain307 = "@ontime.com.ph" ascii wide nocase
        $domain308 = "@onyxfreight.com" ascii wide nocase
        $domain309 = "@oppobihar.in" ascii wide nocase
        $domain310 = "@oppomobilemp.in" ascii wide nocase
        $domain311 = "@opstinagpetrov.gov.mk" ascii wide nocase
        $domain312 = "@orangeone.in" ascii wide nocase
        $domain313 = "@originloger.com" ascii wide nocase
        $domain314 = "@oscarule.xyz" ascii wide nocase
        $domain315 = "@otto-brandes-de.com" ascii wide nocase
        $domain316 = "@otv-international.me" ascii wide nocase
        $domain317 = "@oxse.in" ascii wide nocase
        $domain318 = "@pacificalbd.com" ascii wide nocase
        $domain319 = "@paigelectric.com" ascii wide nocase
        $domain320 = "@pairsigs.com" ascii wide nocase
        $domain321 = "@panpatmos.co.id" ascii wide nocase
        $domain322 = "@pat.ps" ascii wide nocase
        $domain323 = "@pec-warrantgroup.icu" ascii wide nocase
        $domain324 = "@pehledinekam.com" ascii wide nocase
        $domain325 = "@perfectgenerators.com" ascii wide nocase
        $domain326 = "@peterpan.icu" ascii wide nocase
        $domain327 = "@phillqs.com" ascii wide nocase
        $domain328 = "@phoenixloger.com" ascii wide nocase
        $domain329 = "@pipingzone.com" ascii wide nocase
        $domain330 = "@platinships.net" ascii wide nocase
        $domain331 = "@pooldeexcursiones.es" ascii wide nocase
        $domain332 = "@poskcoq.website" ascii wide nocase
        $domain333 = "@poylone.com" ascii wide nocase
        $domain334 = "@ppe-eg.com" ascii wide nocase
        $domain335 = "@primossofa.com" ascii wide nocase
        $domain336 = "@prismindia.in" ascii wide nocase
        $domain337 = "@protectorfiresafety.com" ascii wide nocase
        $domain338 = "@protenginstalacoes.com.br" ascii wide nocase
        $domain339 = "@protistha.com" ascii wide nocase
        $domain340 = "@ptocs.xyz" ascii wide nocase
        $domain341 = "@pure-energy.site" ascii wide nocase
        $domain342 = "@pushpageseo.com" ascii wide nocase
        $domain343 = "@qatarpharmas.org" ascii wide nocase
        $domain344 = "@qoldenhighway.com" ascii wide nocase
        $domain345 = "@qst-hk.com" ascii wide nocase
        $domain346 = "@rajapindah.com" ascii wide nocase
        $domain347 = "@ramseyjonesinc.website" ascii wide nocase
        $domain348 = "@rangersfuel.xyz" ascii wide nocase
        $domain349 = "@rankywise.com" ascii wide nocase
        $domain350 = "@raymond-john.com" ascii wide nocase
        $domain351 = "@razilogs.com" ascii wide nocase
        $domain352 = "@rebu.co.rw" ascii wide nocase
        $domain353 = "@regorns.com" ascii wide nocase
        $domain354 = "@reportlog.top" ascii wide nocase
        $domain355 = "@resulthome.xyz" ascii wide nocase
        $domain356 = "@returntolz.com" ascii wide nocase
        $domain357 = "@rezuit.pro" ascii wide nocase
        $domain358 = "@rianbowmax.com" ascii wide nocase
        $domain359 = "@rishichemlcals.com" ascii wide nocase
        $domain360 = "@rm-elactrical.com" ascii wide nocase
        $domain361 = "@rnedisilk.org" ascii wide nocase
        $domain362 = "@s0udal.com" ascii wide nocase
        $domain363 = "@saharaexpress.com" ascii wide nocase
        $domain364 = "@salasarlamlnates.com" ascii wide nocase
        $domain365 = "@sankapatrol.com" ascii wide nocase
        $domain366 = "@santemoraegypt.com" ascii wide nocase
        $domain367 = "@santiagogarcia.es" ascii wide nocase
        $domain368 = "@sapgroup.com.pk" ascii wide nocase
        $domain369 = "@sarahmarine.com" ascii wide nocase
        $domain370 = "@scandinavian-collection.com" ascii wide nocase
        $domain371 = "@schrodersbnk-uk.com" ascii wide nocase
        $domain372 = "@scientech.icu" ascii wide nocase
        $domain373 = "@scrutifify.xyz" ascii wide nocase
        $domain374 = "@scuksumitomo-chem.co.uk" ascii wide nocase
        $domain375 = "@seabeachaquaparkssh.com" ascii wide nocase
        $domain376 = "@searchnet.co.in" ascii wide nocase
        $domain377 = "@seltrabank.com" ascii wide nocase
        $domain378 = "@servalec-com.me" ascii wide nocase
        $domain379 = "@serviceconsutant.com" ascii wide nocase
        $domain380 = "@shivanilocks.com" ascii wide nocase
        $domain381 = "@shrc-india.com" ascii wide nocase
        $domain383 = "@shreejitransport.com" ascii wide nocase
        $domain384 = "@sicim.icu" ascii wide nocase
        $domain385 = "@sielupz.com" ascii wide nocase
        $domain386 = "@sirafimarine.com" ascii wide nocase
        $domain387 = "@sirohms.com" ascii wide nocase
        $domain388 = "@sitechukandlreland.com" ascii wide nocase
        $domain389 = "@skepsis-sg.icu" ascii wide nocase
        $domain390 = "@s-lbeautycare-az.com" ascii wide nocase
        $domain391 = "@slee-de.me" ascii wide nocase
        $domain392 = "@sobreroartigrafiche.com" ascii wide nocase
        $domain393 = "@solartorbines.com" ascii wide nocase
        $domain394 = "@somakinya.com" ascii wide nocase
        $domain395 = "@sonofgrace.website" ascii wide nocase
        $domain396 = "@sparkintemational.com" ascii wide nocase
        $domain397 = "@spinteng.com" ascii wide nocase
        $domain398 = "@spppumps.co" ascii wide nocase
        $domain399 = "@startranslogistics.com" ascii wide nocase
        $domain400 = "@stemsfruit-za.com" ascii wide nocase
        $domain401 = "@strykeir.com" ascii wide nocase
        $domain402 = "@sunconx.com" ascii wide nocase
        $domain403 = "@suprajit.me" ascii wide nocase
        $domain404 = "@supreme-sg.icu" ascii wide nocase
        $domain405 = "@suryatravels.com" ascii wide nocase
        $domain406 = "@suzukirmkjakarta.com" ascii wide nocase
        $domain407 = "@talleresmartos.com" ascii wide nocase
        $domain408 = "@tashipta.com" ascii wide nocase
        $domain409 = "@tbh-tw.com" ascii wide nocase
        $domain410 = "@techin.icu" ascii wide nocase
        $domain411 = "@technsiem.com" ascii wide nocase
        $domain412 = "@tecnicasreunidas-es.co" ascii wide nocase
        $domain413 = "@tehnopan.rs" ascii wide nocase
        $domain414 = "@teitec.asia" ascii wide nocase
        $domain415 = "@tendertradeforex.co.uk" ascii wide nocase
        $domain416 = "@theroyalsandskohrong.com" ascii wide nocase
        $domain417 = "@totallyanonymous.com" ascii wide nocase
        $domain418 = "@traingle-cn.com" ascii wide nocase
        $domain419 = "@transmeridian-sas.com" ascii wide nocase
        $domain420 = "@trevisqa.com" ascii wide nocase
        $domain421 = "@trirekaperkasa.com" ascii wide nocase
        $domain422 = "@ttkplc.com" ascii wide nocase
        $domain423 = "@turkrom.xyz" ascii wide nocase
        $domain424 = "@tvnqsram.com" ascii wide nocase
        $domain425 = "@twpl.pk" ascii wide nocase
        $domain426 = "@ultrafilterindia.com" ascii wide nocase
        $domain427 = "@unitedparcelsservices.com" ascii wide nocase
        $domain428 = "@universalinks.net" ascii wide nocase
        $domain429 = "@universalsolutions.co.ke" ascii wide nocase
        $domain430 = "@usamilitarydept.com" ascii wide nocase
        $domain431 = "@us-durags.com" ascii wide nocase
        $domain432 = "@varahi.in" ascii wide nocase
        $domain433 = "@vectromtech.com" ascii wide nocase
        $domain434 = "@vipparkingcontrol.com" ascii wide nocase
        $domain435 = "@virqomedical.com" ascii wide nocase
        $domain436 = "@vivaldi.net" ascii wide nocase
        $domain437 = "@wahana-adireksa.co.id" ascii wide nocase
        $domain438 = "@waltartosto.com" ascii wide nocase
        $domain439 = "@waman.in" ascii wide nocase
        $domain440 = "@webdesign-class.site" ascii wide nocase
        $domain441 = "@website-practise.site" ascii wide nocase
        $domain442 = "@weifeng-fulton.com" ascii wide nocase
        $domain443 = "@wepmill.website" ascii wide nocase
        $domain444 = "@wingsun-chine.com" ascii wide nocase
        $domain445 = "@wls-com.me" ascii wide nocase
        $domain446 = "@wonder-thailands.com" ascii wide nocase
        $domain447 = "@workpluswork.com" ascii wide nocase
        $domain448 = "@wtaxtraction.com" ascii wide nocase
        $domain449 = "@wtsele.net" ascii wide nocase
        $domain450 = "@wzwinton.com" ascii wide nocase
        $domain451 = "@xchi1.xyz" ascii wide nocase
        $domain452 = "@xerindo.com" ascii wide nocase
        $domain453 = "@xopservices.com" ascii wide nocase
        $domain455 = "@yandex.com" ascii wide nocase
        $domain456 = "@yandex.ru" ascii wide nocase
        $domain457 = "@zeenatlnc.com" ascii wide nocase
        $domain458 = "@zellico.com" ascii wide nocase
        $domain459 = "@zi-gem.com" ascii wide nocase
        $domain460 = "@zolvtek.com" ascii wide nocase
    condition:
        any of them
}