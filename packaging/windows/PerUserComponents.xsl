<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:wix="http://schemas.microsoft.com/wix/2006/wi">
  <xsl:output method="xml" indent="yes"/>
  <xsl:template match="@*|node()"><xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy></xsl:template>
  <xsl:template match="wix:File/@KeyPath"/>
  <xsl:template match="wix:Component">
    <xsl:copy><xsl:apply-templates select="@*|node()"/>
      <wix:RegistryValue Root="HKCU" Key="Software\Tracehound\Components" Name="{@Id}" Value="1" Type="integer" KeyPath="yes"/>
    </xsl:copy>
  </xsl:template>
  <xsl:template match="wix:Directory">
    <xsl:copy><xsl:apply-templates select="@*|node()"/>
      <wix:Component Id="cleanup_{@Id}" Guid="*">
        <wix:RemoveFolder Id="remove_{@Id}" Directory="{@Id}" On="uninstall"/>
        <wix:RegistryValue Root="HKCU" Key="Software\Tracehound\Components" Name="cleanup_{@Id}" Value="1" Type="integer" KeyPath="yes"/>
      </wix:Component>
    </xsl:copy>
  </xsl:template>
  <xsl:template match="wix:ComponentGroup">
    <xsl:copy><xsl:apply-templates select="@*|node()"/>
      <xsl:for-each select="//wix:Directory"><wix:ComponentRef Id="cleanup_{@Id}"/></xsl:for-each>
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>
