### Vulnerability summary

{{- $critical := 0 }}
{{- $high := 0 }}
{{- $medium := 0 }}
{{- $low := 0 }}
{{- $unknown := 0 }}
{{- range . }}{{- range .Vulnerabilities }}
  {{- if  eq .Severity "CRITICAL" }}{{- $critical = add $critical 1 }}{{- end }}
  {{- if  eq .Severity "HIGH" }}{{- $high = add $high 1 }}{{- end }}
  {{- if  eq .Severity "MEDIUM" }}{{- $medium = add $medium 1 }}{{- end }}
  {{- if  eq .Severity "LOW" }}{{- $low = add $low 1 }}{{- end }}
  {{- if  eq .Severity "UNKNOWN" }}{{- $unknown = add $unknown 1 }}{{- end }}
{{- end }}{{- end }}

<table>
  <tr>
    <th>Critical</th>
    <th>High</th>
    <th>Medium</th>
    <th>Low</th>
    <th>Unknown</th>
  </tr>
  <tr>
    <td align='center'>{{ $critical }}</td>
    <td align='center'>{{ $high }}</td>
    <td align='center'>{{ $medium }}</td>
    <td align='center'>{{ $low }}</td>
    <td align='center'>{{ $unknown }}</td>
  </tr>
</table>
