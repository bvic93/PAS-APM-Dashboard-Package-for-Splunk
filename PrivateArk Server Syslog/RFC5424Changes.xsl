<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method='text' version='1.0' encoding='UTF-8'/>
<xsl:template match="*">
	<xsl:choose>
	    <xsl:when test="audit_record/Rfc5424='yes'">
			<xsl:text>&#x3c;</xsl:text><!-- the character '<' -->
			<xsl:choose>
			   <xsl:when test="audit_record/Severity='Critical'">10</xsl:when>
			   <xsl:when test="audit_record/Severity='Error'">7</xsl:when>
			   <xsl:when test="audit_record/Severity='Info'">5</xsl:when>
			   <xsl:otherwise>0</xsl:otherwise>
			</xsl:choose>
			<xsl:text>&#x3E;</xsl:text> <!-- the character '>' -->
			<xsl:text>1&#x20;</xsl:text> <!-- Syslog Version -->
			<xsl:value-of select="audit_record/IsoTimestamp"/>
			<xsl:text>&#x20;</xsl:text> <!-- space -->
			<xsl:value-of select="audit_record/Hostname"/>
			<xsl:text>&#x20;</xsl:text> <!-- space -->
		</xsl:when>
	    <xsl:when test="monitor_record/Rfc5424='yes'">
			<xsl:text>&#x3c;</xsl:text><!-- the character '<' -->
			<xsl:choose>
			   <xsl:when test="monitor_record/Severity='Info'">5</xsl:when>
			   <xsl:otherwise>5</xsl:otherwise>
			</xsl:choose>
			<xsl:text>&#x3E;</xsl:text> <!-- the character '>' -->
			<xsl:text>1&#x20;</xsl:text> <!-- Syslog Version -->
			<xsl:value-of select="monitor_record/IsoTimestamp"/>
			<xsl:text>&#x20;</xsl:text> <!-- space -->
			<xsl:value-of select="monitor_record/Hostname"/>
			<xsl:text>&#x20;</xsl:text> <!-- space -->
		</xsl:when>
	</xsl:choose>
</xsl:template>
</xsl:stylesheet>