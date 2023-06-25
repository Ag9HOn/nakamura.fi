---
title: "IT-ympäristön pystyttäminen ja ylläpito Kiinassa"
date: 2023-06-25T15:28:11+03:00

categories: ["IT ja Kyberturvallisuus"]
tags: ["Kiina", "IT"]
toc: true
author: "Petteri Nakamura"
---


Viimeisen kuuden ja puolen vuoden aikana olen toiminut useassa eri IT-tehtävissä yrityksessä, jolla on toimisto Kiinassa. Verkko- ja palvelinylläpitäjänä, IT-palvelupäällikkönä ja kyberturvallisuuspäällikkönä  olen saanut ainutlaatuista näkemystä siitä, millaista on ylläpitää ja kehittää IT-ympäristössä Kiinassa. Vaikka monet suomalaiset yritykset toimivat Kiinassa ja on yleisesti tiedossa, että toimintaympäristö maassa on hyvin erilainen kuin Suomessa, en henkilökohtaisesti ole tavannut montaa IT-ammattilaista, jolla on kokemusta ja näkemykstä työskentelystä kiinalaisten kollegoiden kanssa tai IT-ympäristön rakentamisesta, ylläpitämisestä ja kehittämisestä osana suomalaista tai muuta eurooppalaista yritystä Kiinassa. Siksi päätin kirjoittaa aiheesta blogikirjoituksen jakaakseni ajatuksiani suomalaisen IT-ammattilaisen näkökulmasta.

<!--more-->

Teknologia on pääosin samanlaista kaikkialla, mutta suurin osa asioista, joita haluan nostaa esiin, liittyvät enemmänkin kulttuurieroihin kuin tekniikkaan, vaikka tosin kulttuurierotkin aiheuttavat teknisiä haasteita, kuten esimerkiksi niin sanotun "Kiinan suuren palomuurin" muodossa. Muita ympäristöä suunnitellessa huomioonotettavia seikkoja Kiinassa toimittaessa ovat sensuuria, henkilötietojen siirtoa ja keräämistä, kyberturvallisuutta ja vakoilua koskevat säädökset ja lait, jotka vaikuttavat ympäristön arkkitehtuuriin.

# Mitä tietää ennen ympäristön suunnittelua?

IT-ympäristön rakentaminen on pohjimmiltaan teknologian pystyttämistä tukemaan ihmisten suorittamia prosesseja liiketoiminnan pyörittämiseksi. Vaikka IT-ympäristön perustaminen missä tahansa, ei vain Kiinassa, saattaa vaikuttaa siltä, että kyse on vain verkkolaitteiden ja tietokoneiden hankinnasta, niiden asentamisesta paikalleen, käyttöjärjestelmien asentamisesta ja perusverkkopalveluiden määrittämisestä, ennen ympäristön suunnittelua on hyödyllistä ymmärtää nämä kolme ympäristöön vaikuttaa keskenään riippuvaista aspektia. Kuka ympäristöä käyttää ja ylläpitää? Mitä he ympäristöllä tekevät ja miten he tulevat ylläpitämään sitä? Ja lopuksi, mitä laitteita ympäristössä tulee olla ja miten ne täytyy konfiguroida? Liiketoimintaprosessit saattavat olla samat tai samankaltaiset kuin yrityksen muissakin toimipaikoissa, mutta säädökset voivat asettaa niille omat vaatimuksensa, kun otetaan huomioon, mitä tietoja voidaan tai ei voida tallentaa tai lähettää minnekin, mitä asioita ihmiset arvostavat tai miten he suhtautuvat eri asioihin eri kulttuureissa, sekä teknologiat, joita voidaan käyttää missäkin toimipisteessä. Hyvänä esimerkkinä viimeisestä voidaan käyttää Google-palveluiden toimimattomuutta Kiinassa, joten yrityksen, joka käyttää paljon Googlen pilvipalveluita, olisi harkittava lähestymistapansa uusiksi Kiinassa.

## Teknologia

Teknologia on kyse laitteista, tietokoneista, pilvipalveluista ja kommunikaatioyhteyksistä, joita ympäristö tarvitsee liiketoiminnan mahdollistamiseksi. Verkkolaitteet, palvelimet, tietokoneet, verkkoprotokollat jne. ovat samanlaisia kaikkialla, mutta Kiinan erityispiirre on valtion hyvin kontrolloiva suhtautuminen internettiin ja sen palveluihin. Kiinaan IT-ympäristöä perustavalle ulkomaiselle yritykselle tämän kontrollin merkittävin ilmentymä on niin sanottu "Suuri palomuuri", vaikkakin myös muita huomioonotettavia asioita löytyy.

### Suuri palomuuri

Kun ajatellaan IT-ympäristö rakentamista Kiinassa, ensimmäisenä mieleen saattaa tulla niin sanottu "suuri palomuuri". Termi "suuri palomuuri" on kuitenkin harhaanjohtava, koska kyse ei itse asiassa ole erillisestä palomuurijärjestelmästä Kiinan Internetin rajalla, joka valvoo sisääntulevia ja lähteviä paketteja, vaan pikemminkin joukko sääntelyyn ja teknisiin keinoihin perustuvia tapoja sensuroida ja rajoittaa viestintää manner-Kiinan ja muun maailman välillä. Kiinassa on kolme valtion omistamaa teleoperaattoria, jotka hallitsevat maan tietoliikennemarkkinaa: China Telecom, China Unicom ja China Mobile. Valtio myös hallitsee yhteyspisteitä, joiden kautta manner-Kiinan internet yhdistyy maailmanlaajuiseen internetiin. Valtio määrittelee teleoperaattoreille ja muille internet-toimijoille vaatimukset sisällön ja liikenteen sensuroinnista ja valvonnasta ja teleoperaattorit ovat vastuussa pääsyn estämisestä kielletyille sivustoille ja palveluihin. Teleoperaattorit käyttävät velvollisuuksiensa täyttämiseen erilaisia tekniikoita, kuten IP-osoitteiden blokkaamista, DNS-myrkytystä, TCP-reset-hyökkäyksiä, syvän pakettien analysointia, väärennettyjä SSL-juurisertifikaatteja, sekä sovellusten latausten estämistä. Operaattoreiden  suorituskyky ei kuitenkaan ole tasalaatuista, todennäköisesti erilaisten toteutustapojen vuoksi, ja vaikka nämä tekniikat, latenssiin yhdeistettynä, usein tekevät jopa sallituista ulkomaisista palveluista hitaita käyttää Kiinassa, jotkut ISP:t häiritsevät sallittua liikennettä paljon enemmän kuin toiset. Esimerkiksi O365-palveluita ei ole estetty Kiinassa, mutta henkilökohtaisen kokemukseni mukaan, kaikkia kolmea operaattoria testattuani, palvelut näyttävä toimivan parhaiten China Unicomin yhteyksissä, kun taas China Telecomin verkossa jotkin palvelut ovat lähes käyttökelvottomia.

Suuri palomuuri estää pääsyn useimpiin palveluihin, joita suomalaiset tai muut eurooppalaiset käyttäjät ovat tottuneet käyttämään, kuten Googlen-palvelut, mukaanlukien Google-haku, Gmail, YouTube ja Google Maps, Facebook, Twitter, Signal, WhatsApp, ja useimmat tunnetut uutissivustot. Kiinalaiset käyttäjät eivät kuitenkaan  usein edes huomaa ongelmia, koska he ovat tottuneet käyttämään kiinalaisia vastineita, kuten Bilibiliä videoihin, WeChatiä pikaviestintään ja Weiboa twiittaamiseen. Suuri palomuuri on myös auttanut Kiinalaisia teknologiayrityksiä kasvamaan ilman länsimaisia kilpailijoita antaen samalla Kiinan kommunistiselle puolueelle vahvan kontrollin maassa toimivista teknologiayrityksistä, jotka tarjoavat lähes kaikki sosiaalisen median ja muut internetpalvelut. Toisaalta jotkut sivustot ja palvelut Kiinassa ovat estettyjä maan ulkopuolelta, esimerkiksi pääsy julkisiin tietokantoihin, jotka tarjoavat taloudellista tietoa kiinalaisista yrityksistä due diligence -firmoille, estettiin Kiinan ulkopuolelta vuonna 2023. Lisäksi, jos yritys tai yksityishenkilö haluaa perustaa verkkosivuston tai muun verkkopalvelun Kiinassa, tämän on rekisteröitävä sivusto viranomaisille, tai teleoperaattori estää yhteydenotot ko. porttiin.

VPN-palvelujen tarjoaminen Kiinassa on sallittua, jos palvelu on rekisteröity, ja ilmeisesti tämä edellyttää liikenteen rajoitusten käyttöönottoa ja lokien toimittamista viranomaisille pyydettäessä. OpenSSL- ja IPsec-yhteydet toimipisteiden välillä toimivat yleensä, mutta nopeudet voivat pudota ilman havaittavaa syytä tai yhteydet voivat ajoittain lakata kokonaan toimimasta. Olen itse joskus seurannut, kun IPsec-tunneli ei pystynyt muodostamaan yhteyttä kuukausiin, koska IKE-paketit putosivat pois matkalla, mikä esti tunnelin muodostumisen.

Kiinan toimiston ja Kiinan ulkopuolisten palveluiden välisen hteyden laatu tulee testata jokaisella saatavilla olevalla operaattorilla ennen operaattorin valintaa, ja yrityksen kannattaa harkita myös SD-WAN-ratkaisua käytten useampaa operaattoria. Jos yritys tarvitsee luotettavan yhteyden Kiinan ympäristön ja Kiinan ulkopuolisen infrastruktuurin välille, kuten useimmat tarvitsevat, yrityksen kannattaa harkita myös MPLS:ää vaihtoehtona. Vaikka MPLS-yhteys onkin kallis, se tarjoaa luotettavimman yksityisen yhteyden, joka ei kulje julkisen internetin kautta. MPLS:än kanssa kannattaa kuitenkin muistaa, ettei se ole salattu, ja tämä "yksityinen" linja kulkee useiden eri maiden ja operaattoreiden järjestelmien läpi, joilla kaikilla on näkyvyys putkessa kulkevaan liikenteeseen, ellei liikennettä erikseen salata.

### Pilvipalvelut

Kuten aiemmin mainittu, monet muualla käytetyt pilvipalvelut onestetty Kiinassa. Esimerkiksi Googlen tapauksessa esto johtuu Googlen kieltäytymisestä sensuroida sisältöä ja hakutuloksia Kiinan viranomaisten mieleisesti ja Google päätti lopettaa toimintansa maassa. Muilla Yhdysvaltalaisilla teknologiayrityksillä on toimintaa Kiinassa, kuten Apple ja Microsoft, joista jälkimmäinen on lisensoinut O365-palvelunsa kiinalaiselle yritykselle nimeltä 21Vianet, mutta kyseessä on erillinen O365-instanssi, joka ei ole yhteensopiva Kiinan ulkopuolisen version kanssa. Kiinassa toimivien yritysten on mukauduttava sensuurivaatimuksiin ja tiedonjakamiseen viranomaisten kanssa, mutta näidenkään suhteen ei ole järkevää olettaa, että näiden palvelut ovat yhä sallittuja Kiinassa seuraavien 5, 10 tai 15 vuoden kuluttua, varsinkin kun Kiinan hallitus pyrkii jatkuvasti suurempaan teknologiseen omavaraisuuteen ja kyberavaruuden valvontaan. On siis järkevää harkita kiinalaisia vastineita, kuten 21vianetin O365:ttä tai Baidu Cloudia jne. vaihtoehtoisina pilvipalveluina, mutta niiden sovittaminen yrityksen teknologiastackiin voi olla hankalaa ja datavirrat säilytys on harkittava huolellisesti tietosuojauhkiin liittyvien riskien minimoimiseksi sekä asetusten, kuten EU:n yleisen tietosuoja-asetuksen (GDPR) ja Kiinan henkilötietojen suojelulain (PIPL), noudattamiseksi.


### Laitteiden hankinta

Yleensä laitteiden hankkiminen ja asentaminen Kiinassa on helpompaa kuin asentaminen muualla, toimittaminen Kiinaan ja tullin kanssa asioiminen. Kuitenkin leasing-järjestelyt, jotka ovat yleisiä Suomessa, jossa tietokoneet leasataan kolmeksi tai neljäksi vuodeksi ja palautetaan sen jälkeen, eivät näytä olevan yleisiä Kiinassa. On todennäköistä, että yritys joutuu ostamaan kaikki laitteet, mukaan lukien henkilökunnan tietokoneet, ja huolehtimaan niiden koko elinkaaresta itse, mukaan lukien laitteen kierrätys tai myynti.


## Prosessit

Prosesseissa on kysymys siitä, miten yritys toimii saavuttaakseen liiketoimintatavoitteensa. IT:n osalta ne käsittelevät sitä, miten ihmiset käyttävät käytettävissään olevia IT-järjestelmiä, laitteita ja pääsyjä. Prosesseihin vaikuttavat myös ulkoiset säädökset ja yrityksen sisäiset käytännöt. Viimeisen kahden vuosikymmenen aikana sekä Kiinassa että EU:ssa on investoitu voimakkaasti tietosuojan ja kyberturvallisuuden vahvistamiseen, ja tämä trendi on vain kiihtynyt vuodesta 2016 lähtien.


### Lainsäädäntö EU:ssa ja Kiinassa

Sekä EU:n että Kiinan lainsäädännöt käsittelevät yksityisyyden suojaa, kyberturvallisuutta ja kansainvälistä tietosiirtoa. EU pyrkii luomaan yhtenäisen lainsäädännön sekä tietosuojastandardit koko unionin alueella sen kansalaisten henkilötietojen suojelemiseksi. Toisaalta Kiina keskittyy kansallisen turvallisuuden ja suvereniteetin suojelemiseen, mikä on johtanut tiukempiin sääntöihin liittyen tietojen säilyttämiseen ja siirtämiseen sen rajojen ulkopuolelle.

Molemmat alueet todennäköisesti jatkavat lainsäädännön kehittämistä vastaamaan uusien teknologioiden, kuten tekoäly, lohkoketjut ja pilvipalvelut, haasteisiin ja yritysten on kyettävä mukautumaan nopeasti kehittyväänlainsäädäntöön. Tämä sopeutuminen edellyttää investointeja kyberturvallisuuteen, avoimuuteen henkilötietojen käsittelyssä, tietosuojan parantamiseen ja tietojen luokittelun ja käsittelyn prosessien kehittämiseen, jotta yritykset voivat tietää tarkalleen, mitä tietoja varastoidaan ja siirretään missäkin. Myös säädösten ristiriidat voivat aiheuttaa liiketoimintariskejä.

Vaikka EU:n ja Kiinan kyberturvallisuus- ja tietosuojalakien takana on yhteneviä tavoitteita henkilötietojen suojelun ja kyberturvallisuuden parantamisen suhteen, EU:n lainsäädäntö korostaa yksilön oikeuksia ja vaatii yrityksiltä tiukkoja tietosuojan ja tietoturvan standardeja sekä rajoittaa EU-kansalaisten tietojen siirtoa maihin, joiden lainsäädäntö ei takaa vastaavaa suojaa, Kiinan lainsäädäntö keskittyy enemmänkin valtion kontrolliin ja kansallisen turvallisuuden kysymyksiin, vaatien yrityksiltä yhteistyötä, sisältäen tietojen luovuttamisen viranomaisille pyydettäessä, sekä määrittää rajoituksia tietojen siirtämiselle Kiinan ulkopuolelle koskien Kiinan kansalaisten henkilötietoja, sekä erittäin laajasti määriteltyjä Kiinan kansallista turvallisuutta ja etua koskevia tietoja.

Arvioitavat lait sisältävät:

**EU:n lainsäädäntö:**

- Direktiivi 95/46/EC (1995): Ensimmäinen merkittävä EU:n tietosuojalainsäädäntö.
- Direktiivi 2002/58/EC (ePrivacy-direktiivi, 2002): Keskittyy sähköisen viestinnän yksityisyyteen ja turvallisuuteen.
- Direktiivi 2013/40/EU (NIS-direktiivi, 2016): Ensimmäinen EU:n laajuinen kyberturvallisuuslainsäädäntö.
- Yleinen tietosuoja-asetus (GDPR, 2016): Korvasi direktiivin 95/46/EC tuoden merkittäviä muutoksia.
- Whistleblower-direktiivi (2019): Tarjoaa suojaa työntekijöille, jotka ilmoittavat laittomista toimista tai väärinkäytöksistä, mukaan lukien tietomurrot.
- NIS2-direktiivi (2023): Päivitys NIS-direktiivin, joka pyrkii parantamaan kyberturvallisuuden tasoa kaikkien EU:n jäsenvaltioiden ja toimijoiden keskuudessa.

**Kiinan lainsäädäntö:**

- Tietoturvalaki (2006): Kiinan ensimmäinen tietoturvaan ja yksityisyyden suojaan keskittyvä laki.
- Tietoverkkojen turvallisuuslaki (2013): Korostaa tietoturvan merkitystä kansallisen turvallisuuden kannalta.
- Kyberturvallisuuslaki (2017): Kiinan ensimmäinen kattava kyberturvallisuuslainsäädäntö.
- Tietoturvallisuuslaki (DSL, 2021): Keskittyy laajasti tietoturvaan ja käsittelyvaatimuksiin.
- Henkilötietojen suojalaki (PIPL, 2021): Kiinan ensimmäinen laki, joka erityisesti käsittelee henkilötietojen suojaa.
- Vastavakoilulaki (Päivitetty, 2023): Laaja päivitys olemassa olevaan vastavakoilulainsäädäntöön, joka kieltää kaiken "kansalliseen turvallisuuteen ja etuihin" liittyvän tiedon siirtämisen ulkomaille ja laajentaa vakoilun määritelmää. Laki myös antaa vastavakoiluun liittyvää tutkimusta tekeville viranomaisille oikeuden päästä käsiksi tietoihin, elektronisiin laitteisiin ja henkilökohtaiseen omaisuuteen sekä mahdollisuuden kieltää maasta poistumisen.

Kansainvälisen yrityksen on päätettävä tarkalleen, mitä tietoja se voi säilyttää Kiinassa ja mitä tietoja se voi siirtää Kiinasta ulos. Esimerkkejä ovat Active Directory -rakenteen suunnittelu, HR-järjestelmät, asiakas- ja käyttäjätietokannat sekä muut järjestelmät, jotka tulee suunnitella niin, että vain tarpeelliset tiedot siirretään toimipaikkojen välillä ja eturistiriidat voidaan välttää.


### Yrityksen käytännöt

Liiketoimintaprosessit ja yrityksen käytännöt, jotka toimivat Suomessa tai EU:ssa, eivät välttämättä ole suoraan sovellettavissa Kiinassa. Esimerkiksi yrityksen käytäntö saattaa vaatia, että kaikki ohjelmistot käyttäjien tietokoneilla ajetaan peruskäyttäjäoikeuksilla eikä korotetuilla järjestelmänvalvojan oikeuksilla, mutta esimerkiksi jotkut Kiinan verotusilmoitusten tekoon käytetyt sovellukset, joita yritysten on pakko käyttää, saattavat vaatia paikallisia järjestelmänvalvojan oikeuksia toimiakseen. Yrityksellä on oltava suunnitelmat siihen, miten tällaiset tilanteet voidaan hoitaa.

Toinen esimerkki on, että yritys saattaa vaatia kaiken viestinnän ulkoisten asiakkaiden tai sidosryhmien kanssa tapahtuvan käyttäen yrityksen sähköpostia tai Teamsin tai muun collaborointisovelluksen kautta. Myös tiedostojen lähettämisen yhteydessä saatetaan vaatia turvallisia tiedostojakoja tai salattuja sähköposteja. Kuitenkin Kiinassa sähköpostia pidetään erittäin virallisena viestintätapana, ja ihmiset käyttävät usein WeChatia työviestintään ja tiedostojen lähettämiseen, koska se on kätevä käyttää ja kaikki muutkin käyttävät sitä, huolimatta siitä, että se on tunnetusti raskaasti valvottu ja sensuroitu palvelu. WeChatin käyttöä ei välttämättä myöskään voi välttää, koska asiakkaat saattavat vaatia sen käyttöä. Yrityksellä tulee olla selkeät ohjeet WeChatin käytölle ja varmistaa esimerkiksi, että palomuurisäännöt sallivat tai kieltävät sen käytön yrityksen käytäntöjen mukaisesti ja että helpdesk tietää, miten tukea käyttäjiä sallittujen kommunikaatiovälineiden suhteen.


## Ihmiset

Kulttuurierot vaikuttavat siihen, miten ihmiset suhtautuvat teknologiaan ja vuorovaikuttavat sen kanssa ja minkälaista tukea heille on järjestettävä.


### Työvälineet

Suomessa on yleinen käytäntö, että yritykset tarjoavat työvälineet henkilöstölle, mutta monet kiinalaiset suosivat BYOD (Bring Your Own Device, tuo oma laite) -käytäntöjen ja yrityksen tarjoamien tietokoneiden yhdistelmää. Joskus myös yritykset suosivan sitä, että työntekijät käyttävät omia tietokoneitaan, koska näin yritys voi säästää rahaa tietokoneiden ostamisessa. Käyttäjät saattavat myös käyttää tietokoneitaan kuin omia henkilökohtaisia tietokoneitaan ja haluavat asentaa niihin WeChatin, Baidu Cloud -agentin synkronoimaan omia tiedostojaan tai muita omia suosikkiohjelmistojaan yrityksen tarjoamien ohjelmistojen sijaan. Keskustelin kerran yrityksen tietokoneiden päivittämisestä erään kiinalaisen kanssa, ja hän ehdotti että koska kiinalaiset mielellään vertailevat millaisia bonuksia yritykset ovat heille antaneet kiinalaisena uutena vuonna, meidän kannattaisi antaa uudet tietokoneet lahjana kiinalaisena uutena vuonna. Tämä oli mielenkiintoinen idea, joka toi hyvin esiin omastani täysin erilaisen suhtautumisen yrityksen tietokoneisiin. Tietokoneet ietokoneet eivät olleet vain yrityksen tarjoamia työkaluja, vaan henkilökohtaisia esineitä, jotka annettiin työntekijöille.


### Viestintä

Olen huomannut, että kiinalaiset ovat hyvin avoimia ja heidän kanssaan on helppo keskustella. Suomalaisten ja Kiinalaisten viestintätyyleissä on myös monia yhtäläisyyksiä. Henkilöstö noudattaa yleensä ohjeita ja käytäntöjä, todennäköisesti paremmin kuin suomalaiset, vaikka niiden syitä ei olisikaan perusteltu heille. Toisaalta suomalaiset saattavat olla hitaita vastaamaan sähköposteihin tai saattavat jättää vastaamatta kokonaan kunnes ovat varmoja jostakin. Työelämä Kiinassa on erittäin kilpailuhenkistä ja nopeita tuloksia arvostetaan. Kiinalaiset löytävätkin hyvin nopeasti jonkin pikaratkaisun, jos he eivät saa vastausta helpdesk-tiketteihinsä tarpeeksi nopeasti, vaikka se ei olisikaan linjassa yrityksen käytäntöjen kanssa. Pikaratkaisu voi myös edelleen sisältää laittoman ohjelmiston asentamisen tai lisenssigeneraattorin lataamisen, vaikkakin tämä on vähenemään päin.


### Kielimuuri

Kielimuurin ylittäminen ja kulttuurierojen ymmärtäminen ovat suurimmat haasteet kiinalaisten kanssa toimiessa. Englannin kielen taidon taso vaihtelee suuresti, joten kärsivällisyys, selkeä viestintä, sekä olettamusten välttäminen ja sen sijaan kysyminen ovat avainasemassa. Itse olen huomannut, että mandariinikiinan opiskelu ja keskeisten kulttuuristen piirteiden tunteminen, kuten hierarkian kunnioitus, epäsuora viestintä, vahva ryhmäorientaatio, kova kilpailuhenkisyys ja "kasvojen" käsite, on auttanut suuresti viestinnässä kiinalaisten kollegoideni kanssa..

Näiden erojen käsittelemiseksi yrityksen käytäntöjen tulee määritellä selkeät säännöt yrityksen laitteiden ja sallittujen sovellusten käyttöön ottaen huomioon sekä yrityksen vaatimukset että kiinalainen kulttuuri. Henkilöstölle tulee tarjota runsaasti koulutusta käytännöistä ja tukea tulee olla tarvittaessa saatavilla nopeasti. Lisäksi, koska henkilökohtaiset suhteet ovat erittäin tärkeitä Kiinassa, yrityksen tulisi investoida siihen, että Euroopassa työskentelevät henkilöt, jotka tekevät säännöllisesti yhteistyötä Kiinan toimiston kanssa, mukaan lukien helpdesk-insinöörit, jos Kiinan toimistolle tarjotaan helpdesk-palvelut etänä jostakin muusta sijainnista, käyvät tapaamassa kiinalaisia kollegoitaan. Tämä parantaa yhteistyötä ja ongelmanratkaisua suuresti, auttaa ihmisiä muissa toimistoissa ymmärtämään ongelmat Kiinan toimistossa ja päinvastoin, sekä auttaa myös kiinalaisia kollegoita helpommin hakemaan apua.


# Johtopäätökset

IT-ympäristön perustaminen Kiinassa, kuten missä tahansa muuallakin, edellyttää kattavaa ymmärrystä yrityksen tarpeista, henkilöstön käyttäytymisestä ja vaatimuksista sekä toimintaan liittyvästä lainsäädännöstä. Kuitenkin kiinalaisen kontekstin erityispiirteet tuovat mukanaan joitakin erityisiä haasteita, jotka on otettava huomioon tehokkaan toiminnan takaamiseksi.

Meillä on taipumus nähdä internet yhtenäisenä palveluna, joka on samanlainen kaikkialla, vaikka näin ei todellisuudessa ole. Kiinan suuri palomuuri ja tiukat tieto- ja kyberturvallisuuslait vaikuttavat digitaaliseen ympäristöön meille tuntemattomilla tavoilla, jotka vaikuttavat päätöksiin pilvipalveluista, laitteiden hankinnasta ja yhteyksistä. Huolimatta näistä haasteista, tehokkaan IT-ympäristön rakentamisen periaatteet pysyvät samoina. Vaatimukset täytyy ymmärtää, kartoittaa  vaihtoehdot ja sovittaa strategia paikallisiin vaatimuksiin.

Kulttuuriset vivahteet, jotka ovat osa liiketoimintaprosesseja ja yrityksen käytäntöjä, ovat toinen keskeinen tekijä Kiinassa toimiessa. Vaikka olennaiset osat pysyvät samoina kuin muissakin maissa, yksityiskohdat, kuten suhtautuminen BYOD:iin ja yrityksen tarjoamiin laitteisiin, nopeiden vastausten ja ongelmanratkaisun merkitys, sekä henkilökohtaisten suhteiden tärkeys lisäävät monimutkaisuutta, joka on otettava huomioon.

Kielimuurin ylittäminen ja henkilökohtaisten suhteiden luominen työntekijöiden kesken johtaa parempaan yhteistyöhön ja molemminpuoliseen ymmärrykseen Ihmiskeskeinen lähestymistapa on universaalisti tärkeä, mutta se on erityisen merkittävä Kiinassa, jossa henkilökohtaisilla suhteilla on ratkaiseva rooli.

IT-ympäristön luominen Kiinassa tuo mukanaan omat erityispiirteensä ja mukautuminen on avainasemassa kun mietitään, miten erityisvaatimuksiin sopeudutaan, miten opettaa yrityksen käytännöt henkilöstölle, miten jalkauttaa yrityksen prosessit, miten sopeutua paikalliseen sääntelyyn ja miten suojata yrityksen data, järjestelmät ja liiketoiminta uhilta. Samankaltaisuuksien tunnistaminen ja erojen käsittely avaa tien onnistuneelle, tehokkaan, toimivan ja vaatimustenmukaisen IT-ympäristön luomiselle.


**Lähteet:**
- https://protonvpn.com/blog/great-firewall-china/
- https://digital-strategy.ec.europa.eu/en/policies/cybersecurity-strategy
- https://gdpr-info.eu/
- https://eur-lex.europa.eu/legal-content/FI/TXT/?uri=CELEX%3A32016R0679
- https://eur-lex.europa.eu/eli/dir/2016/1148/oj
- https://digital-strategy.ec.europa.eu/en/policies/nis-directive
- https://www.europarl.europa.eu/thinktank/en/document/EPRS_BRI(2021)689333
- https://www.nis-2-directive.com/
- https://eur-lex.europa.eu/legal-content/Fi/ALL/?uri=CELEX%3A32002L0058
- https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32019L1937
- https://flk.npc.gov.cn/detail2.html?MmM5MDlmZGQ2NzhiZjE3OTAxNjc4YmY4Mjc2ZjA5M2Q%3D
- http://www.npc.gov.cn/englishnpc/c23934/202112/1abd8829788946ecab270e469b13c39c.shtml
- https://digichina.stanford.edu/work/translation-personal-information-protection-law-of-the-peoples-republic-of-china-effective-nov-1-2021/


