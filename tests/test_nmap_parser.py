"""Parseo determinista de nmap -sV (base de la busqueda de CVEs en NVD)."""

from app.services.nmap_parser import evidencia_compacta, parsear_nmap

SALIDA = """\
Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-13 19:00 -03
Nmap scan report for 192.168.1.50
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1 (DSA)
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
| ssl-cert: Subject: commonName=x
23/tcp   open  telnet      Linux telnetd
MAC Address: 08:00:27:AA:BB:CC (Oracle VirtualBox virtual NIC)
"""


def test_extrae_producto_y_version():
    p = {x.puerto: x for x in parsear_nmap(SALIDA)}
    assert (p[21].producto, p[21].version) == ("vsftpd", "2.3.4")
    assert (p[22].producto, p[22].version) == ("OpenSSH", "4.7p1")
    assert (p[80].producto, p[80].version) == ("Apache httpd", "2.2.8")


def test_servicio_sin_version():
    p = {x.puerto: x for x in parsear_nmap(SALIDA)}
    assert p[23].version == ""


def test_scripts_se_asignan_al_puerto_y_el_ruido_se_descarta():
    p = {x.puerto: x for x in parsear_nmap(SALIDA)}
    assert any("ftp-anon" in e for e in p[21].extras)
    assert not any("ssh-hostkey" in e for e in p[22].extras)
    assert not any("ssl-cert" in e for e in p[80].extras)


def test_no_arrastra_lineas_ajenas_al_ultimo_puerto():
    p = {x.puerto: x for x in parsear_nmap(SALIDA)}
    assert p[23].extras == []


def test_evidencia_compacta_incluye_cada_puerto():
    texto = evidencia_compacta(parsear_nmap(SALIDA))
    assert "21/tcp" in texto and "80/tcp" in texto and "Starting Nmap" not in texto


def test_sin_puertos_abiertos():
    assert parsear_nmap("Nmap scan report for 10.0.0.1\nAll 1000 ports closed\n") == []
