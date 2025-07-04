{{- define "buzzcore.name" -}}
{{- default .Release.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "buzzcore.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- include "buzzcore.name" . | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "buzzcore.labels" -}}
app.kubernetes.io/name: {{ include "buzzcore.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "buzzcore.selectorLabels" -}}
app.kubernetes.io/name: {{ include "buzzcore.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}