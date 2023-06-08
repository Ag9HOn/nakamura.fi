---
title: "D.. Mitä? SPF, DKIM ja DMARC; Mitä ne tarkalleen ottaen ovat"
date: 2019-01-09T19:28:11+03:00

categories: ["Kyberturvallisuus"]
tags: ["DMARC", "DKIM", "SPF", "Sähköposti",]
toc: false
author: "Petteri Nakamura"
---

IT on täynnä akronyymeja eikä sähköposti ole poikkeus. Tässä artikkelissa selitän, kuinka nämä kolme auttavat taistelemaan roskapostia ja muita haitallisia sähköposteja vastaan, joita me kaikki saamme joka päivä. Kaikki kolme toimivat kulissien takana eivätkä ole näkyvissä sähköpostipalveluiden loppukäyttäjille, elleivät nämä erityisesti lähde etsimään niitä. 


# Taustaa

Olen usein verrannut sähköpostia postikorttien lähettämiseen. Kirjoitat viestisi kovalle paperille, lisäät vastaanottajan osoitteen, allekirjoitat nimesi ja lähetät sen matkaan. Postitoimisto toimittaa kortin, mutta vastaanottajalla, viestin saatuaan, ei ole mitään keinoa tietää, että kortti on todella tullut sinulta. Sähköposti syntyi aikana, jolloin ei osattu ennakoida valtavia ongelmia, joita roskapostista ja kalastelusta aiheutuu nykyään, joten sähköpostin alkuperäinen standardi ja toteutukset eivät tarjoa mitään autentikointimenetelmiä. Kuka tahansa voikin lähettää sähköpostia kenenä tahansa mistä tahansa. Kirjoita vain mitä haluat korttiin, esitä ketä tahansa henkilöä, ja lähetä viesti matkaan. Matkitulla henkilöllä ei ole asiasta mitään tietoa ellei vastaanottaja ota häneen yhteyttä.

Tämä luo kaksijakoisen ongelman. Viestien vastaanottajan täytyy tietää, mitkä viestit ovat aitoja ja mitkä eivät. Toisaalta lähettäjän täytyy pystyä vakuuttamaan vastaanottaja siitä, tämän lähettämä viesti todella tuli häneltä. Olisi myös hienoa, jos hänellä olisi keino tietää, jos joku lähettää viestejä hänen nimissään sekä estää se, koska lähettäjälle voi aiheutua spoofingista merkittävää mainehaittaa.

Koska roskapostin ja phishingin ongelmat ovat yleistyneet, eri tahot ovat kehittäneet erilaisia menetelmiä sähköpostien tarkistamiseksi voidakseen arvioida, ovatko ne aitoja, ei-toivottuja, huijauksia vai suorastaan vaarallisia ja haitallisia. Tämä perustuu pitkälti arvailuun, mutta 2000-luvun alussa on nähty uusia, hitaasti jalansijaa saavuttavia,  tekniikoita tämän ongelman ratkaisemiseksi. Vastuu tarkistaa ja kunnioittaa lähettävän organisaation asettamia politiikkoja kuuluu täysin sähköpostin vastaanottajalle, mutta SPF, DKIM ja DMARC muodostavat yhdessä työkalupakin sähköpostijärjestelmien ylläpitäjille, jotka mahdollistavat sääntöjen julkaisun siitä, mistä he sallivat sähköpostin lähettämisen, miten he kryptografisesti todistavat, että viestit todella tulevat heidän järjestelmistään, sekä vastaanottaville järjestelmille ohjeiden lähettämisen viestien tarkistamiseksi, mitä tehdä viesteille, jotka eivät läpäise tarkastuksia, ja miten raportoida takaisin lähtöjärjestelmille vastaanotetuista viesteistä.


# SPF

SPF tulee sanoista "Sender Policy Framework" ja se on käytännössä tapa, jolla domainin ylläpitäjä voi julkaista luettelon Internet-osoitteista, jotka saavat lähettää sähköpostia domainin nimissä, sekä politiikan siitä, mitä tehdä luvattomista lähteistä tuleville viesteille. Jatkaaksemme postitoimistovertausta, yritys julkaisisi politiikan: "yrityksemme lähettää kaiken postinsa tietyn postitoimiston kautta Helsingissä, olkaa hyvät ja hylätkää kaikki viestit, jotka eivät tule sieltä", vastaanottava postitoimisto tarkistaa sitten leiman postimerkissä ennen sen toimittamista vastaanottajalle, ja hylkää viestin, jos se ei ole leimattu valtuutetussa postitoimistossa.

SPF julkaistiin [kokeellisena vuonna 2006](https://tools.ietf.org/html/rfc4408) ja [ehdotettuna standardina vuonna 2014](https://tools.ietf.org/html/rfc7208). [Hang Hun ja Gang Wangin](https://people.cs.vt.edu/gangwang/usenix-draft.pdf) Virginia Techista mukaan [Alexan](https://aws.amazon.com/alexa-top-sites/) miljoonan suosituimman sivuston verkkotunnuksista 44,9%:lla oli voimassa olevat SPF-tietueet tammikuussa 2018 (40% vuonna 2015), ja tuhannen suosituimman sivuston osalta käyttöaste oli 73%. Hu:n ja Wangin mukaan 31 suurista 35 sähköpostipalvelun tarjoajasta, jotka testattiin heidän tutkimuksessaan, tukee SPF:ää ja [Google raportoi](https://security.googleblog.com/2013/12/internet-wide-efforts-to-fight-email.html), että vuonna 2016 heidän näkemistään kaikista vastaanotetuista sähköposteista 95,7% oli suojattu SPF:llä. Näistä kolmesta tekniikasta SPF on siis laajimmin käytössä.


# DKIM

Vaikka SPF:ää käytetään määrittämään, mistä viesti saa tulla, "Domain Key Identified Mail":ia, eli DKIM:iä, käytetään lähettäjän tunnistamiseen. Postitoimistoesimerkissä postipalvelua käyttävä yritys on julkaissut avaimen, jolla voidaan tarkistaa heidän lähettämiensä viestien allekirjoitukset. Työntekijä kirjoittaa viestin ja jättää sen yritykselle toimitettavaksi. Yritys ottaa viestin, allekirjoittaa sen, sekä liittää viestiin mukaan ohjeet siitä, mistä löytää avain allekirjoituksen tarkistamiseen. Viesti annetaan sitten valtuutetulle postitoimistolle, joka toimittaa sen vastaanottajalle toimituksesta vastaavalle postitoimistolle. Ennen toimitusta, vastaanottava postitoimisto löytää yrityksen allekirjoituksella varustetun viestin, etsii julkisen avaimen lähettävän yrityksen antamien ohjeiden mukaan ja tarkistaa allekirjoituksen. Jos allekirjoitus vastaa julkista avainta, vastaanottaja tietää, että viestin lähettäjällä oli yrityksen lupa lähettää viesti.

[Proposed Standard](https://tools.ietf.org/html/rfc4871) DKIM:lle julkaistiin vuonna 2007 ja [Internet Standard](https://tools.ietf.org/html/rfc6376) julkaistiin vuonna 2011. Google raportoi, että vuonna 2016 heidän näkemistään kaikista tulevista sähköposteista 87,6% oli DKIM-suojattuja, ja Hu ja Wang raportoivat, että 27 suurista 35 sähköpostipalvelun tarjoajasta heidän tutkimuksessaan tukee DKIM:ä.

# DMARC

"Domain-based Message Authentication, Reporting and Conformance", eli DMARC, on uusin kolmesta ja se luotiin SPF:n ja DKIM:n päälle, jotta lähettäjät voisivat julkaista politiikkoja koskien tunnistamattomien sähköpostien käsittelyä, sekä vastaanottaa raportteja vastaanottajilta sähköpostien autentikoinnista. Postitoimistoesimerkissä yritys julkaisee nyt myös politiikan, joka sanoo jotakin sen suuntaista kuin "Käytämme SPF:ää ja DKIM:iä sähköpostiemme autentikointiin, vaadimme kaikkien lähtevien sähköpostien noudattavan SPF-politiikkaa ja olevan allekirjoitettu yrityksemme toimesta. Olkaa hyvät ja hylätkää kaikki viestit, jotka eivät täytä näitä vaatimuksia, ja lähettäkää raporttinne tähän osoitteeseen". Työntekijä toimittaa viestin yritykselle toimitettavaksi, yritys allekirjoittaa sen ja antaa sen valtuutetulle postitoimistolle, viesti toimitetaan vastaanottavalle postitoimistolle, joka ensin tarkistaa, onko lähettäjällä DMARC-politiikka, tarkistaa sitten, että viesti tuli vaaditulta postitoimistolta, tarkistaa, että viestin allekirjoitus vastaa yrityksen julkaisemaa julkista avainta, ja toimittaa viestin vastaanottajalle vasta kun kaikki vaatimukset on täytetty. Lopuksi vastaanottava postitoimisto kokoaa raportin kaikista sen vastaanottamista viesteistä ko. lähettäjältä ja toimittaa koontiraportin yrityksen määrittelemään osoitteeseen.

DMARC:n luonnosmäärittelyä on ylläpidetty vuodesta 2012 lähtien ja [informatiivinen Request for Comments](https://tools.ietf.org/html/rfc7489) julkaistiin vuonna 2015. Hu ja Wang raportoivat, että vuonna 2018 16 suurimmasta 35 sähköpostipalvelun tarjoajasta tukee DMARC:ia ja 5,1% miljoonasta verkkotunnuksesta on voimassaolevat DMARC-tietueet. Tuhannen suosituimman verkkotunnuksen kohdalla luku on huikea 41%, mikä on mielestäni erittäin hyvä luku ottaen huomioon kuinka uusi protokolla on sekä SPF:n 73% käyttöaste.


# Matalalla roikkuvat hedelmät

SPF:n asettaminen on jo melko standardi toimenpide yritysten sähköpostiasetuksissa, olitpa sitten tekemässä asetuksiaä SAAS-palvelussa kuten O365 tai G Suite, tai perustamassa omaa sähköpostipalvelinta. Ensimmäisessä tapauksessa palveluntarjoaja antaa ohjeet SPF-tietueen luomiseen, joka domainin omistajan tulee luoda julkiseen nimipalveluun. Jälkimmäisessä ylläpitäjä tarvitsee lähettävän sähköpostipalvelimen julkisen IP-osoitteen DNS:ää varten. Jos sähköpostia lähettäviä palvelimia on useita, tämä aiheuttaa sen, että sähköpostin vastaanottajat hylkäävät joitakin sähköposteja, jos kaikkia käytössä olevia IP-osoitteita ei ole määritelty.

DKIM:n kanssa täytyy luoda yksityinen/julkinen avainpari, julkaista julkinen avain ja käyttää yksityistä avainta lähtevän sähköpostin allekirjoittamiseen. Ylläpidetyn järjestelmän palveluntarjoaja tekee suurimman osan tästä työstä ja asiakkaan tulee vain julkaista julkinen avain, mutta itse ylläpidetyssä ratkaisussa ylläpitäjän tulee konfiguroida kaikki itse. DKIM ei kuitenkaan sisällä politiikkoja, joten sen asettaminen ei vaikuta muiden, allekirjoittamattomien, sähköpostien toimittamiseen, ennen kuin DMARC-tietue on asetettu.

DMARC otetaan käyttöön luomalla _dmarc -tietue verkkotunnukselle DNS:ssä. DMARC mahdollistaa myös politiikan luomisen, joka antaa kaikkien viestien mennä läpi ja antaa vastaanottajille sähköpostiosoitteen, johon raportit tulee lähettää. Jos infrastruktuuri on jo olemassa, eikä olla varmoja mistä kaikki sähköposti lähetetään, tietue voidaan luoda ja alkaa kerätä raportteja kaikkien lähettäjien selvittämiseksi. Kun SPF ja/tai DKIM on asetettu oikein, politiikkaa voidaan alkaa asteittain kiristää ja seurata sen vaikutusta.

Jos verkkotunnusta ei ole tarkoitettu lähettämään sähköpostia lainkaan, on järkevää silti asettaa DMARC Reject -politiikka, jotta kukaan ei voi väärentää viestejä

# Lähteet ja viitattu aineisto

- https://people.cs.vt.edu/gangwang/usenix-draft.pdf
- https://security.googleblog.com/2013/12/internet-wide-efforts-to-fight-email.html
- https://tools.ietf.org/html/rfc4408
- https://tools.ietf.org/html/rfc7208
- https://tools.ietf.org/html/rfc4871
- https://tools.ietf.org/html/rfc6376
- https://tools.ietf.org/html/rfc7489
- https://aws.amazon.com/alexa-top-sites/
- https://en.wikipedia.org/wiki/Sender_Policy_Framework
- https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail
- https://en.wikipedia.org/wiki/DMARC
