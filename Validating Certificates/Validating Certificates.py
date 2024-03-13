from subprocess import Popen, PIPE, STDOUT

# Helper function to run OpenSSL commands and capture output
def run_openssl_command(command):
    process = Popen(command, stdout=PIPE, stderr=STDOUT, shell=True)
    output, _ = process.communicate()
    return output.decode('utf-8')

# Paths to certificates and keys
cacert_path = 'cacert.crt'
intercacert_path = 'Intercacert.crt'
cert_path = 'cert.crt'

# Check if cert2 is self-signed
cert_self_signed_check = run_openssl_command(f'openssl verify -CAfile {cert_path} {cert_path}')

# Check subject of cert
cert_subject_check = run_openssl_command(f'openssl x509 -in {cert_path} -noout -subject')

# Verify cert with the CA and intermediate certificates
cert_chain_verification = run_openssl_command(f'openssl verify -CAfile {cacert_path} -untrusted {intercacert_path} {cert_path}')

# Prepare output for cert
output_cert = {
    'cert_self_signed_check': cert_self_signed_check,
    'cert_subject_check': cert_subject_check,
    'cert_chain_verification': cert_chain_verification,
}

output_cert
