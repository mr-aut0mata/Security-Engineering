rule Suspicious_ICS_Calendar_Invite {
    meta:
        description = "Detects ICS files with suspicious external links or auto-processing flags used in phishing"
        author = "mr-aut0mata"
        date = "2025-12-17"
        reference = "https://sublime.security/blog/ics-phishing-stopping-a-surge-of-malicious-calendar-invites/"
    strings:
        $header = "BEGIN:VCALENDAR" nocase
        
        // malicious use of the ATTACH property to reference external URLs
        $attach_uri = "ATTACH;FMTTYPE=text/html" nocase
        $attach_link = "ATTACH:http" nocase

        // Common phishing keywords in the DESCRIPTION field (ADD MORE OVER TIME)
        $desc_urgency_1 = "DESCRIPTION:Action Required" nocase
        $desc_urgency_2 = "DESCRIPTION:Security Alert" nocase
        $desc_urgency_3 = "DESCRIPTION:Mandatory" nocase
        
        // Suspicious Organizers (generic placeholder logic)
        $organizer_spoof = "ORGANIZER;CN=\"Security Team\"" nocase

    condition:
        $header and (
            ($attach_uri or $attach_link) or 
            ($organizer_spoof and any of ($desc_urgency*))
        )
}
