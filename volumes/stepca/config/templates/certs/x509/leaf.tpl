{
        "subject": {
                "commonName": {{ toJson .Subject.CommonName }},
                "organization": "Smallstep CA UI"
        },
{{- if .SANs }}
        "sans": {{ toJson .SANs }},
{{- end }}
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
        "keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
        "keyUsage": ["digitalSignature"],
{{- end }}
        "extKeyUsage": ["serverAuth"],
        "issuingCertificateURL": "http://pki.example.com/intermediate_ca.crt",
        "crlDistributionPoints": "http://pki.example.com/intermediate_ca.crl"
}
