metadata:
  annotations:
    a: {{ .Values.x | toYaml | indent 2 }}
# {{ quote "{{/*" }}
  name: {{ .Values.y }}
# {{ quote "*/}}" }}
