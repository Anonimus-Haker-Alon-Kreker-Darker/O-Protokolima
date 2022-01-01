# O-Protokolima
Internet protokoli
Sloj aplikacije
BGP • DHCP • DNS • FTP • HTTP • IMAP • IRC • LDAP • MGCP • NNTP • NTP • POP • RIP • RPC • RTP • SIP • SMTP • SNMP • SOCKS • SSH • Telnet • TLS/SSL • XMPP
Transportni sloj
TCP • UDP • DCCP • SCTP • RSVP • ECN
Internet sloj
IP • IPv4 • IPv6 • ICMP • ICMPv6 • IGMP • IPsec
Sloj veze
ARP • NDP • OSPF • Tunneling protocol • L2TP • PPP • Media access control • Eternet • DSL • ISDN • FDDI

Internet protokol
----------------

IP (internet protokol) (engl. Internet Protocol) je protokol trećeg sloja OSI referentnog modela (sloja mreže). Sadrži informacije o adresiranju, čime se postiže da svaki mrežni uređaj (računar, server, radna stanica, interfejs rutera) koji je povezan na internet ima jedinstvenu adresu i može se lako identifikovati u celoj internet mreži, a isto tako sadrži kontrolne informacije koje omogućuju paketima da budu prosleđeni (rutirani) na osnovu poznatih IP adresa. Ovaj protokol je dokumentovan u RFC 791 i predstavlja sa TCP protokolom jezgro internet protokola, TCP/IP stek protokola (engl. Transmission Control Protocol/Internet Protocol).

IP ne zahteva prethodno upostavljanje veze u trenutku slanja podatka, već računar koji šalje podatke pokušava sve dok ne prosledi poruku (best effort) model, prenos podataka je relativno nepouzdan, što znači da nema gotovo nikave garancije da će poslati paket zaista i doći do odredišta nakon što je poslat. Sam paket u procesu prenosa se može promeniti, zbog različitih osnovnih prenosnih pravaca, može se dogoditi da segmenti ne stižu po redosledu, mogu se duplicirati ili potpuno izgubiti tokom prenosa. Ukoliko aplikacija zahteva pouzdanost, koriste se mehanizmi TCP protokla u sloju iznad samog IP protokola. TCP protokol je isto zadužen za definisanje redosleda paketa koji stižu (sekvence).

S obzirom da je sam koncept IP protokola oslobođen mehanizama koji osiguravaju pouzdanost, sam proces usmeravanja (rutiranja) paketa unutar mreže je relativno brz i jednostavan.

Internet protokol kao mrežni protokol
-------------------------------------

Glavni članak: Mrežni protokol
Protokol – termin koji koristimo, predstavlja konvenciju, standard ili set pravila koje treba poštovati da bismo uspešno uspostavili i kontrolisali komunikaciju (razmenu podataka). Jednostavnije rečeno, protokoli predstavljaju pravila kojima su definisani sintaksa, semantika i sinhronizacija komunikacije. Nazivamo ih još mrežnim ili internet protokolima. Postoje različiti mrežni protokoli, pri čemu svaki ima posebno mesto i vrši svoju ulogu. Par koji sačinjavaju internet protokol IP i protokol za kontrolu prenosa TCP su najbitniji od mrežnih protokola i termin TCP/IP protokol stek označava skup najkorišćenijih od njih.

Funkcije
------------

IP ima tri primarne funkcije:

Adresiranje (definiše način dodele internet adresa), internet moduli koriste adrese koje paketi nose u IP zaglavlju kako bi ih prosledili dalje ka destinaciji.
Glavni članak: Internet adresa
Rutiranje, određivanje putanje za prenos podataka sa jednog računara na drugi bez prethodnog uspostavljanja veze (engl. connectionless), po (engl. best-effort) modelu.
Fragmentaciju i ponovno sastavljanje paketa kada je potrebno kako bi se preneli kroz mrežu koja ima manji MTU (engl. maximum transmission unit).

IPv4 internet protokol verzija 4
--------------------------------

Ova verzija internet protokola je aktuelna, definisana je u dokumentu RFC 791, septembra 1981. godine.

Zaglavlje internet protokola IPv4
IP protokol, takođe, opisuje standardnu strukturu paketa kojim podaci putuju kroz mrežu. Princip je enkapsulacija (pakovanje) informacije u strukture pogodne za prenos. Analogija je poštanski paket. U zaglavljju paketa, pored adrese pošiljaoca i primaoca podataka, stoje još i informacije o samom paketu koje obaveštavaju kako paket treba da putuje (koliko je stanica već prošao, da li se može deliti u manje pakete, itd.)

bit 0-3	4-7	8-15				20-31
Verzija	Dužina	Tip servisa	Ukupna dužina
Identifikacija	0	
D

F

M

F

Mesto fragmenta
TTL	Protokol	Čeksuma (Provera bitskih grešaka)
Izvorišna internet adresa
Odredišna internet adresa
Opcije
Podatak (TCP segment ili UDP datagram)
Navodimo informacije o poljima u zaglavlju IP [1]:

Verzija (4 bita): Prikazuje iznos verzije kako bi se mogao dozvoliti razvoj protokola. Vrednost polja je 4.
Dužina internet Zaglavlja (IHL) (4 bita): Dužina zaglavlja u 32-bitnoj reči. Minimalna vrednost je pet za minimalnu dužinu zaglavlja od 20 bajta.
Tip servisa TOS (engl. Type of Service) (8 bita): U prethodnom opisu servisa, ovo polje se odnosilo na polje tip Servisa i određivalo je pouzdanost, prednost, odlaganje i parametre propusne moći. Ovakva iterpretacija je sada zamenjena. Prvih 6 bita polja Tipa Servisa sada pripada polju DS (engl. Differentiated Services), a ostala 2 bita rezervisana su za polje ECN (engl. Explicit Songestion Notification).
Ukupna dužina (16 bita): Ukupna dužina datagrama, uključujući zaglavlje i podatke, izraženo je u bajtovima (oktetima).
Identifikacija (16 bita): Niz brojeva, koji zajedno sa izvorišnom adresom, odredišnom adresom i korisničkim protokolom namerava da jedinstveno identifikuje paket. Prema tome, ovaj broj bi trebalo da bude jedinstven za izvorišnu adresu, odredišnu adresu i korisnički protokol datagrama dok god je on u internetu.
Kontrolni bitovi (3 bita): Samo dva od ovih bita su trenutno definisana. MF (engl. More Fragment) se koristi za fragmentaciju i ponovno sklapanje, kao što je malopre objašnjeno. Bit DF (engl. Dont Fragment) zabranjuje fragmentaciju kada se to traži. Ovaj bit može biti od velike koristi kada se zna da destinacija nema kapaciteta da sklopi fragmente. Ipak, ako je ovaj bit postavljen, paket će biti odbačen ako premaši maksimalnu veličinu mreže na nekoj ruti. Da se ovo ne bi desilo, bilo bi pametno koristiti izvorišno rutiranje da bi se zaobišle mreže koje imaju definisanu malu maksimalnu veličinu paketa.
Mesto fragmenta (13 bita): Pokazuje gde je u originalnom datagramu mesto ovom fragmentu, iskazano u 64 bita. To znači da fragmenti koji nisu poslednji fragment moraju da sadrže polje podataka koje je deljivo sa 64 bita u dužini.
Vreme života (TTL) (8 bita): Pokazuje koliko dugo, u skokovima, je dozvoljeno datagramu da bude u internetu. Svaki ruter koji procesira datagram mora da smanji TTL za najmanje jedan, tako da je TTL donekle sličan brojaču skokova.
Protokol (8 bita): Pokazuje protokol višeg nivoa kome treba proslediti paket; prema tome, ovo polje identifikuje tip zaglavlja segmenta (sloj transporta). Vrednosti 1 (00000001) za ICMP, 6 (00000110) za TCP, 17 (00010001) za UDP
Zaštitna suma (Čeksuma) (16 bita): Kod za detektovanje greške koji je privezan samo zaglavlju. Zbog menjanja nekih polja tokom puta (npr. vreme u životu, fragmentaciona polja), ovo polje se reverifikuje i procenjuje u svakom ruteru. Polje se formira tako što se uzmu jedinice iz 16 bita i dodaju se sve jedinice iz svih 16-bitnih reči u zaglavlju. Zbog računanja, polja čeksume su inicijalizovana na vrednost nula.
Izvorišna adresa (32 bita): Kodirano da bi se dozvolile različite kombinacije bita za specificiranje mreže ili sistema prikačenog na mrežu.
Odredišna adresa (32 bita): Iste katakteristike kao izvorišna adresa.
Opcije (promenljivo): Kodira opcije tražene od strane pošiljaoca.
Punjenje (promenljivo) (engl. Padding): Koristi se da bi se moglo garantovati da je zaglavlje datagrama spoj 32-bitnih dužina.
Podaci višeg sloja (promenljivo): Ovo polje mora biti spoj 8-bitnih dužina celih brojeva. Maksimalna dužina datagrama (polja podataka + zaglavlja) je 65,535 bajtova

IPv5
----------

Ono što bi se moglo nazvati IPv5 protokolom je postojalo samo kao eksperimentalni protokol u realnom vremenu nazvan ST2, ne-IP protokol i opisan je u RFC 1819. Ovaj protokol je napušten u korist RSVPa.

IPv6 internet protokol verzija 6
---------------------------------

Zaglavlje internet protokola IPv6
Zaglavlje internet protokola IPv6 je u odnosu na zaglavlje IPv4 protokola dosta pojednostavljeno. Naime, od njega zadržava samo 3 polja (verzija, izvorišna adresa i odredišna adresa) i uvodi dodatnih 5 polja.

bit 0-3	4-11	12-15	16-23	24-31
Verzija	Tip prometa	Oznaka toka
Dužina podatka	Sledeće zaglavlje	Ograničenje skoka
Izvorišna internet adresa (128 bita)
Odredišna internet adresa (128 bita)
Podatak (TCP segment ili UDP datagram)
Verzija (4 bita): Verzija internet protokola, vrednost je 6.
Tip prometa (DS/ECN) (8 bita): Ovo polje se odnosilo na polje Traffic Class i bilo je rezervisano za upotrebu od strane početnih čvorova i/ili prosleđujućih rutera da bi se identifikovalo i razlikovalo između različitih klasa prioriteta IPv6 paketa. Prvih šest bita polja Klasa Saobraćaja sada se odnosne na polje DS (differentiated services), a ostalih 2 bita su rezervisana za polje ECN (explicit congestion notification).
Oznaka toka (20 bita): Može biti korišćeno od strane hosta da obeleži one pakete sa kojima ruteri treba da posebno postupaju u okviru mreže.
Dužina podataka (16 bita): Dužina ostatka IPv6 paketa koji prati zaglavlje, u oktetima. Drugim rečima, ovo je kompletna dužina svih produženih zaglavlja plus dužina PDU-a transportnog nivoa.
Sledeće zaglavlje (8 bita): Identifikuje tip zaglavlja koje prati IPv6 zaglavlje. Ovo može biti i IPv6 produženo zaglavlje ili zaglavlje višeg sloja, kao što je TCP ili UDP.
Ograničenje skoka (8 bita): Preostali broj dozvoljenih skokova za ovaj paket. Ograničenje skokova je postavljeno na željenu maksimalnu veličinu od strane izvorišta i dekrementira se od strane svake tačke koja prosleđuje paket. Paket se odbacuje kada vrednost ovog polja postane nula. Ovo je pojednostavljen postupak u odnosu na postupak koji treba da se obavi sa poljem dužine života kod IPv4. Saglasnost je bila da dodatni napor u obračunu vremenskih intervala u IPv4 nije doneo nikakvu značajnu vrednost protokolu. U stvari, IPv4 ruteri, kao glavno pravilo, tretirali su TTL polje kao polje ograničenja skoka.
Izvorišna adresa (128 bita): Adresa pošiljaoca paketa (uređaja predajne strane).
Odredišna adresa (128 bita): Adresa određenog primaoca paketa. Ovo ne mora, u suštini, da bude krajnja odredišna adresa ako je prisutno zaglavlje rutiranja.
IPv6 unapređenja u odnosu na IPv4:
Proširen adresni prostor: IPv6 koristi 128-bitne adrese umesto 32-bitnih adresa koje je koristio IPv4. Izračunato je da ovo omogućava 7 * 1023 jedinstvenih adresa po kvadratnom metru na površini Zemlje.[2] Čak i ako se adrese nevešto dodeljuju, ovaj adresni prostor deluje bezbedno.
Unapređen mehanizam opcija: Opcije IPv6 su smeštene u zasebna fakultativna zaglavlja koja se nalaze između IPv6 zaglavlja i zaglavlja transportnog sloja. Većina od ovih neobaveznih zaglavlja ne bivaju ispitana ili obrađena od strane rutera na putu paketa. Ovo pojednostavljuje i ubrzava rutersku obradu IPv6 paketa u odnosu na IPv4 datagrame. Ovo, takođe, dodatno uprošćava postupak dodavanja dodatnih opcija.
Povećana fleksibilnost adresiranja: IPv6 uključuje koncept anycast adrese, do koje se paket isporučuje samo jednim putem. Skalabilnost multikast rutiranja je unapređena tako što je dodat opseg polje za multikast adrese.
Pomoć za dodeljivanja sredstava: IPv6 omogućava označavanje paketa za sporiji protok ako pošiljalac traži poseban postupak. Ovo uključuje pomoć za specijalni saobraćaj kao što je real-time video.
