		<!-- 
			Add the following lines to the <SIEM>.XML if needed
			They should be placed between the </xsl:for-each> and </xsl:template> markers right after the syslog/audit_record section
		-->
		<xsl:for-each select="syslog/monitor_record">CEF:0|<xsl:value-of select="Vendor"/>|<xsl:value-of select="Product"/>|<xsl:value-of select="Version"/>|<xsl:value-of select="AverageExecutionTime"/>|<xsl:value-of select="MaxExecutionTime"/>|<xsl:value-of select="AverageQueueTime"/>|<xsl:value-of select="MaxQueueTime"/>|<xsl:value-of select="NumberOfParallelTasks"/>|<xsl:value-of select="MaxParallelTasks"/>|<xsl:value-of select="TransactionCount"/>|<xsl:value-of select="CPUUsage"/>|<xsl:value-of select="MemoryUsage"/>|<xsl:value-of select="DriveFreeSpaceInGB"/>|<xsl:value-of select="DriveTotalSpaceInGB"/>|<xsl:value-of select="SyslogQueueSize"/>
		</xsl:for-each>