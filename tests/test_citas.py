"""R-05: toda cita debe existir textualmente en la evidencia (tolerante a '|_' y multilinea)."""

from app.services.llm_service import find_quote_source

EVIDENCIA = (
    "PUERTOS ABIERTOS:\n"
    "21/tcp open ftp vsftpd 2.3.4\n"
    "|_ftp-anon: Anonymous FTP login allowed (FTP code 230)\n"
    "22/tcp open ssh OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)\n"
)


def test_cita_exacta():
    assert find_quote_source("21/tcp open ftp vsftpd 2.3.4", EVIDENCIA)


def test_tolera_prefijo_y_mayusculas():
    assert find_quote_source("FTP-ANON: anonymous ftp login allowed", EVIDENCIA)


def test_cita_multilinea_consecutiva():
    cita = "21/tcp open ftp vsftpd 2.3.4\n|_ftp-anon: Anonymous FTP login allowed (FTP code 230)"
    assert find_quote_source(cita, EVIDENCIA)


def test_cita_inventada_se_rechaza():
    assert not find_quote_source("80/tcp open http Apache httpd 2.2.8", EVIDENCIA)


def test_lineas_no_consecutivas_se_rechazan():
    cita = "21/tcp open ftp vsftpd 2.3.4\n22/tcp open ssh OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)"
    assert not find_quote_source(cita, EVIDENCIA)


def test_cita_vacia_o_corta():
    assert not find_quote_source("", EVIDENCIA)
    assert not find_quote_source("ftp", EVIDENCIA)
