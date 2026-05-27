# Glossaire Rainfall — pour la correction

Ce projet couvre **3 grandes familles de techniques** réparties sur 10 + 3 niveaux. Voici les termes qui reviennent le plus souvent dans les walkthroughs, classés par fréquence et importance pédagogique.

---

## 1. Concepts fondamentaux (présents PARTOUT)

### Setuid bit (`-rwsr-s---`)
Le bit `s` sur le binaire fait qu'il s'exécute avec les droits de son **propriétaire**, pas de l'utilisateur qui lance. C'est pour ça qu'on cherche à lancer `system("/bin/sh")` : le shell hérite des droits de `levelN+1` → on peut lire son `.pass`.
> Présent : tous les niveaux.

### Little-endian
L'architecture x86 stocke les entiers **octet de poids faible en premier**. Une adresse `0x08048444` s'écrit en mémoire `\x44\x84\x04\x08`.
> Présent : level1, 2, 3, 4, 5, 6, 7, 9, bonus0, bonus1, bonus2.

### Adresse de retour (saved EIP / @retour)
À chaque `call`, le CPU empile l'adresse de l'instruction suivante. Au `ret`, il la dépile vers EIP. **Écraser l'adresse de retour = contrôler où le programme va sauter.**
> Présent : level1, 2, bonus0, bonus2.

### Stack frame (saved EBP / padding d'alignement)
- `push %ebp ; mov %esp, %ebp` ouvre la frame.
- `and $0xfffffff0, %esp` aligne sur 16 octets (peut ajouter du padding).
- Disposition typique : `[buffer][padding][saved EBP][@retour]`.
> Présent : level1, 2, bonus0.

---

## 2. Les 3 grandes failles exploitées

### A. Buffer overflow (stack)
Écrire au-delà d'un buffer local pour écraser ce qui est plus loin sur la pile (saved EBP, @retour, autres variables).
- **`gets()`** : LA fonction à signaler immédiatement — aucune borne.
- **`strcpy()`** : pas de borne non plus.
- **`strncpy()` piège** : ne pose **pas** de `\0` si l'input fait pile la taille max → fusion avec le buffer suivant (bonus0).
- **`memcpy(buf, src, count*4)` avec `count` signé** : un négatif passe `count<10` mais `count*4` débordé en `size_t` donne une grande taille (bonus1).
> Niveaux : level1, level2, bonus0, bonus1, bonus2.

### B. Format string
`printf(buf)` au lieu de `printf("%s", buf)` → l'input devient le **format** lui-même.
- **`%x` / `%p`** : LIT la pile.
- **`%n`** : ÉCRIT (4 octets) le nombre de caractères déjà affichés à une adresse trouvée sur la pile.
- **`%hn`** (2 octets) / **`%hhn`** (1 octet) : écriture **octet par octet** pour ne pas devoir afficher des millions de caractères.
- **`%N$x`** : syntaxe **positionnelle** — lit l'argument à la position N de la pile.
- **Compteur monotone** : `%n` ne fait que monter ; on écrit les octets dans l'ordre **croissant des valeurs** + on rajoute 256 par tour (`compteur_cible = 256 + octet_voulu`).
> Niveaux : level3, level4, level5.

### C. Heap overflow
Débordement d'un chunk `malloc` vers le chunk voisin (chunks contigus, séparés par un **header malloc de 8 octets** sur i386).
- Écraser un **pointeur de fonction** voisin (level6).
- Écraser le **pointeur d'une struct** pour transformer le `strcpy` suivant en **écriture arbitraire** (level7).
- **Out-of-bounds read** : lire `auth[32]` alors que `auth = malloc(4)` tombe dans le chunk `service` adjacent (level8).
- **Vtable hijack C++** : écraser le `vtable_ptr` d'un objet voisin (level9).
> Niveaux : level6, level7, level8, level9.

---

## 3. Techniques d'exploitation (le « comment on saute »)

### Return-to-function
Rediriger `@retour` vers une fonction **déjà présente** dans le binaire (souvent une fonction "cachée" jamais appelée : `run()`, `o()`, `n()`, `m()`).
> level1, level5, level6, level7.

### ret2shellcode
Injecter ses propres instructions machine (shellcode) dans le buffer, puis y sauter.
> level2 (via strdup → heap), level9 (via fausse vtable), bonus0, bonus2 (via env var).

### Shellcode `execve("/bin/sh")` (i386, 23–25 octets)
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3...
```
- `xor eax,eax` → 0
- empile `"/bin//sh\0"` sur la pile
- `mov $0xb, %al` → syscall n°11 = `execve`
- `int $0x80` → kernel.
- Pas d'octets nuls → passe les `strcpy`.
> level2, level9, bonus0, bonus2.

### GOT overwrite (Global Offset Table)
La GOT est le « carnet d'adresses » des fonctions libc résolues à l'exécution. Écraser l'entrée d'une fonction (`exit@got`, `puts@got`) la redirige vers une autre adresse contrôlée.
- Adresse de la **case GOT** = fixe dans le binaire (insensible à l'ASLR).
- Trouvée via `objdump -R ./binary | grep <func>`.
> level5 (via format string), level7 (via heap overflow).

### NOP sled (`\x90 * N`)
Suite d'instructions « ne fait rien » placée avant le shellcode pour ne pas devoir viser pile son premier octet — n'importe quelle adresse dans le sled fonctionne.
> bonus0, bonus2.

### Shellcode en variable d'environnement
Quand NX est désactivé (`readelf -l ./bin | grep GNU_STACK` → `RWE`), on stocke le shellcode dans une variable d'env, on récupère son adresse avec un mini-`getenv` compilé, et on l'utilise comme cible de saut.
> bonus0, bonus2.

### Fake vtable (C++)
L'appel virtuel C++ fait **double indirection** : `b → vtable_ptr → vtable[0] → fonction`. On ne peut donc pas pointer directement sur le shellcode : on fabrique une fausse vtable de 4 octets dans le buffer qu'on contrôle, puis on pointe le `vtable_ptr` corrompu vers cette fausse vtable.
> level9.

---

## 4. Outils d'analyse

| Outil | À quoi ça sert | Niveaux où il sert |
|---|---|---|
| `file` | type de binaire (ELF 32-bit, statique, etc.) | level0 |
| `ltrace` | trace les appels de bibliothèque (`gets`, `printf`...) | level1, level2 |
| `strace` | trace les appels système | — |
| `strings` | chaînes en clair | — |
| `objdump -d` | désassemble | tous |
| `objdump -R` | relocations dynamiques (= **adresses GOT**) | level5, level7 |
| `objdump -t` | table des symboles (adresse des globales comme `m`) | level4 |
| `gdb` / `pwndbg` | debug, breakpoints, lecture registres, désassemblage | tous |
| `Ghidra` | décompilation, reconstruction des sources | tous |

---

## 5. Astuces tactiques

- **Trouver l'offset de l'input sur la pile** : envoyer `AAAA + %p %p %p...` et chercher `0x41414141` (level3).
- **Trouver l'offset jusqu'à EIP** : envoyer un motif unique `BBBBCCCCDDDDEEEE...` et lire `info registers eip` après crash (bonus0, bonus2).
- **Garder le shell vivant** : `( ./exploit ; cat )` — le `cat` garde stdin ouvert.
- **Adresses heap stables** : pas d'ASLR effectif sur le heap dans RainFall → l'adresse `0x0804a008` est réutilisable.
- **ASLR ne touche QUE la libc**, pas le binaire ni ses globales/GOT.

---

## 6. Pièges où l'évaluateur peut t'attendre

1. **Pourquoi 76 octets et pas 64 ?** (level1) → 64 (buffer) + 8 (padding `and 0xfffffff0`) + 4 (saved EBP). Distinguer **taille du buffer** vs **offset jusqu'à @retour**.
2. **Pourquoi le filtre `0xb` casse ret2libc ?** (level2) → la stack et la libc commencent par `0xb...`. Le heap (`0x0804...`) passe.
3. **`%hhn` vs `%n`** (level4, level5) → `%hhn` écrit 1 octet → padding réduit → tient dans les 512 octets de `fgets`.
4. **`exit` vs `_exit` dans la GOT** (level5) → ce ne sont **pas** les mêmes entrées, viser la bonne.
5. **Pourquoi double indirection en C++** (level9) → l'appel virtuel passe `objet → vtable → fonction`, donc on ne peut pas sauter direct au shellcode.
6. **Signed/unsigned mismatch** (bonus1) → `count` lu en signé pour le test, en non-signé par `memcpy`.
7. **Préfixe long = cible plus tôt** (bonus2) → contre-intuitif : `LANG=fi` fait tomber l'@retour à `argv[2][18]` au lieu de 30, donc dans la zone copiée.

---

## 7. Récap par niveau — quelle technique pour quel niveau

| Niveau | Faille principale | Technique d'exploitation |
|---|---|---|
| level0 | `atoi(argv[1]) == 423` | Trouver la constante en hex (`0x1a7`) |
| level1 | `gets()` buffer overflow | Return-to-function (`run`) |
| level2 | `gets()` + filtre @retour `0xb...` | ret2shellcode via `strdup` (heap) |
| level3 | `printf(buf)` format string | `%n` pour écrire `0x40` dans la globale `m` |
| level4 | `printf(buf)` format string | `%hhn` octet par octet pour écrire `0x1025544` dans `m` |
| level5 | `printf(buf)` + `exit(1)` | **GOT overwrite** de `exit` via `%hhn` |
| level6 | `strcpy` heap overflow | Écraser pointeur de fonction voisin |
| level7 | double `strcpy` heap overflow | **GOT overwrite** de `puts` via écriture arbitraire |
| level8 | `auth[32]` out-of-bounds read | Faire tomber `service` à `auth+0x20` |
| level9 | `memcpy` heap overflow (C++) | Fake vtable + shellcode |
| bonus0 | `strncpy` sans `\0` + `strcpy`/`strcat` | Shellcode en env + NOP sled |
| bonus1 | `memcpy` avec `count` signé | Écraser `count` adjacent avec `"FLOW"` |
| bonus2 | `strcat` après préfixe `$LANG` | `LANG=fi` pour décaler la cible + shellcode env |
| bonus3 | *non fait* | — |
