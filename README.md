# S/MIME Signer Relay

This SMTP relay will sign emails passing through it with S/MIME for emails it has
the appropriate certificate for.

## Config

```toml
client_id = "smime-relay.as207960.ltd.uk" # SMTP Server/Client ID to advertise
listen_addr = "localhost:2525" # Where to listen for incoming connections
smime_cert_dir = "./p12/" # Folder to look for PKCS#12 files to sign emails
smime_pass = "" # Password used to encrypt PKCS#12 files at rest
ip_acl = ["127.0.0.0/8"] # IP CIDRs that are allowed to send emails through this serer

[tls_conf]
cert_file = "./tls.crt" # TLS Certificate chain for STARTTLS 
key_file = "./tls.key" # TLS Key for STARTTLS

# Relay server that will be responsible for onward delivery, DKIM signign etc
[onward_delivery]
server = "smtp-relay.gmail.com" 
port = 25
use_tls = true # If false STRATTLS will be used if available but not requiered, if true STARTTLS is required.
```

### PKCS#12 files

PKCS#12 files in DER format should be put in the configured directory, named according to
the `From` email address; for example for `test@example.com` should be in `./p12/test@example.com`.