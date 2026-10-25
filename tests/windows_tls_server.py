"""One offline TLS test server; synthetic key in a temporary directory, no trust-store changes."""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile

with tempfile.TemporaryDirectory(prefix='emudhra-tls-test-') as directory:
    cert = Path(directory) / 'test.pem'
    key = Path(directory) / 'test.key'
    subprocess.run([os.environ['EMUDHRA_TEST_OPENSSL'], 'req', '-x509', '-newkey', 'rsa:2048',
                    '-sha256', '-nodes', '-days', '1', '-subj', '/CN=localhost',
                    '-keyout', str(key), '-out', str(cert)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(15)
        print(listener.getsockname()[1], flush=True)
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(5)
            try:
                with context.wrap_socket(connection, server_side=True):
                    pass
            except ssl.SSLError:
                pass  # The client must reject this untrusted certificate.
