{{/*
=============================================================================
EXAMPLE CONFIGURATION - Getting Started Template
=============================================================================
This file is provided as a starting point for deployments. It should be
reviewed and modified to match your specific infrastructure requirements,
security policies, and operational needs before use in production.
=============================================================================
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "artifact-keeper.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "artifact-keeper.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "artifact-keeper.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "artifact-keeper.labels" -}}
helm.sh/chart: {{ include "artifact-keeper.chart" . }}
{{ include "artifact-keeper.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: artifact-keeper
{{- end }}

{{/*
Selector labels
*/}}
{{- define "artifact-keeper.selectorLabels" -}}
app.kubernetes.io/name: {{ include "artifact-keeper.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Backend selector labels
*/}}
{{- define "artifact-keeper.backend.selectorLabels" -}}
{{ include "artifact-keeper.selectorLabels" . }}
app.kubernetes.io/component: backend
{{- end }}

{{/*
Web selector labels
*/}}
{{- define "artifact-keeper.web.selectorLabels" -}}
{{ include "artifact-keeper.selectorLabels" . }}
app.kubernetes.io/component: web
{{- end }}

{{/*
Edge selector labels
*/}}
{{- define "artifact-keeper.edge.selectorLabels" -}}
{{ include "artifact-keeper.selectorLabels" . }}
app.kubernetes.io/component: edge
{{- end }}

{{/*
PostgreSQL selector labels
*/}}
{{- define "artifact-keeper.postgres.selectorLabels" -}}
{{ include "artifact-keeper.selectorLabels" . }}
app.kubernetes.io/component: postgres
{{- end }}

{{/*
Meilisearch selector labels
*/}}
{{- define "artifact-keeper.meilisearch.selectorLabels" -}}
{{ include "artifact-keeper.selectorLabels" . }}
app.kubernetes.io/component: meilisearch
{{- end }}

{{/*
Trivy selector labels
*/}}
{{- define "artifact-keeper.trivy.selectorLabels" -}}
{{ include "artifact-keeper.selectorLabels" . }}
app.kubernetes.io/component: trivy
{{- end }}

{{/*
DependencyTrack selector labels
*/}}
{{- define "artifact-keeper.dtrack.selectorLabels" -}}
{{ include "artifact-keeper.selectorLabels" . }}
app.kubernetes.io/component: dependency-track
{{- end }}

{{/*
Database URL helper — returns the full DATABASE_URL string
*/}}
{{- define "artifact-keeper.databaseUrl" -}}
{{- if .Values.postgres.enabled -}}
postgresql://{{ .Values.postgres.auth.username }}:{{ .Values.postgres.auth.password }}@{{ include "artifact-keeper.fullname" . }}-postgres:5432/{{ .Values.postgres.auth.database }}
{{- else -}}
postgresql://{{ .Values.externalDatabase.username }}:{{ .Values.externalDatabase.password }}@{{ .Values.externalDatabase.host }}:{{ .Values.externalDatabase.port }}/{{ .Values.externalDatabase.database }}
{{- end -}}
{{- end }}

{{/*
ServiceAccount name
*/}}
{{- define "artifact-keeper.serviceAccountName" -}}
{{- if .Values.backend.serviceAccount.create }}
{{- default (printf "%s-backend" (include "artifact-keeper.fullname" .)) .Values.backend.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.backend.serviceAccount.name }}
{{- end }}
{{- end }}
