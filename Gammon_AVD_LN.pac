function FindProxyForURL(url, host) {

var privateIP = /^(0|10|127|192\.168|172\.1[6789]|172\.2[09]|172\.3[01]|169\.254|192\.88\.99)\.[0-9.]+$/; 
var resolved_ip = dnsResolve(host);

// Don’t send non-FQDN or private IP auths to us
if (isPlainHostName(host) || isInNet(resolved_ip, "192.0.2.0","255.255.255.0") || privateIP.test(resolved_ip)) return "DIRECT";

// FTP goes directly 
if (url.substring(0,4) == "ftp:") return "DIRECT";

// Updates are directly accessible 
if ((localHostOrDomainIs(host, "trust.zscaler.com")) && (url.substring(0,5) == "http:" || url.substring(0,6) == "https:")) return "DIRECT"; 

// Example Don’t send to Zscaler Internal Domains
//if (
//dnsDomainIs(host, ".name.of.customer.domain.to.bypass1.com") || //dnsDomainIs(host, ".name.of.customer.domain.to.bypass2.com"))
//return "DIRECT";
// Example Don’t send to Zscaler Customer Internal IP Addresses
//if (
//shExpMatch(host, "8.8.8.*") || //shExpMatch(host, "4.4.4.*"))
//return "DIRECT";

// Azure Bypass for Authentication 
if ( dnsDomainIs(url, ".microsoftonline.com") || dnsDomainIs(url, ".microsoftonline-p.net") || dnsDomainIs(url, ".azure.com")) return "DIRECT";

// Azure and Microsoft Application Bypasses 
if ( shExpMatch(url, ".microsoft.com") || 
shExpMatch(url, ".windows.net") || 
shExpMatch(url, ".sharepointonline.com") || 
shExpMatch(url, ".office.com") || 
shExpMatch(url, ".office.net") || 
shExpMatch(url, ".onmicrosoft.com") || 
shExpMatch(url, ".lync.com") || 
shExpMatch(url, ".sfbassets.com") || 
shExpMatch(url, ".trafficmanager.net") || 
shExpMatch(url, ".msecnd.net") || 
shExpMatch(url, ".aspnetcdn.com") || 
shExpMatch(url, ".azure.net") || 
shExpMatch(url, ".secure.skypeassets.com") || 
shExpMatch(url, ".tenor.com") || 
shExpMatch(url, ".microsoftstream.com") || 
shExpMatch(url, ".skype.com") || 
shExpMatch(url, ".live.com") || 
shExpMatch(url, ".skypeforbusiness.com") || 
shExpMatch(url, ".office365.com")) 
return "DIRECT";

// Specific to WVD 
if ( shExpMatch(url, ".wvd.microsoft.com") || 
shExpMatch(url, ".core.windows.net") || 
shExpMatch(url, "login.windows.net") || 
shExpMatch(url, ".servicebus.windows.net") || 
shExpMatch(url, ".warmpath.msftcloudes.com") || 
shExpMatch(url, ".azureedge.net") || 
shExpMatch(url, ".events.data.microsoft.com") || 
shExpMatch(url, ".msftconnecttest.com") || 
shExpMatch(url, ".microsoftonline.com") || 
shExpMatch(url, ".prod.do.dsp.mp.microsoft.com") || 
shExpMatch(url, ".sfx.ms") || 
shExpMatch(url, ".digicert.com") || 
shExpMatch(url, "aka.ms") || 
shExpMatch(url, ".aka.ms") || 
shExpMatch(url, ".prod.cms.rt.microsoft.com"))
return "DIRECT";

/* AVD URL Whitelist */
	if 
	(	
		shExpMatch(url, "login.microsoftonline.com") ||
		shExpMatch(url, "*.wvd.microsoft.com") ||
		shExpMatch(url, "catalogartifact.azureedge.net") ||
		shExpMatch(url, "gcs.prod.monitoring.core.windows.net") ||
		shExpMatch(url, "kms.core.windows.net") ||
		shExpMatch(url, "azkms.core.windows.net") ||
		shExpMatch(url, "mrsglobalsteus2prod.blob.core.windows.net") ||
		shExpMatch(url, "wvdportalstorageblob.blob.core.windows.net") ||
		shExpMatch(url, "oneocsp.microsoft.com") ||
		shExpMatch(url, "www.microsoft.com") ||
		shExpMatch(url, "login.windows.net") ||
		shExpMatch(url, ".events.data.microsoft.com") ||
		shExpMatch(url, ".msftconnecttest.com") ||
		shExpMatch(url, "aadcdn.msftconnecttest.com") ||
		shExpMatch(host, "aadcdn.msftconnecttest.com") ||
		shExpMatch(url, ".prod.do.dsp.mp.microsoft.com") ||
		shExpMatch(url, ".sfx.ms") ||
		shExpMatch(url, ".digicert.com") ||
		shExpMatch(url, ".azure-dns.com") ||
		shExpMatch(url, ".azure-dns.net") ||
		shExpMatch(url, ".msftauth.net") ||
    shExpMatch(url, "aadcdn.msftauth.net") ||
    isInNet(host, "169.254.169.254", "168.63.129.16")
	)
	return "DIRECT"; 
	
	// Specific to Gammon 
if ( shExpMatch(url, "gammonconstruction.com") || 
shExpMatch(host, "*.gammonconstruction.com") || 
shExpMatch(host, "adfs.gammonconstruction.com"))
return "DIRECT";

// // Send to Zscaler Proxy //
return "PROXY ${COUNTRY_GATEWAY_FX}:9443; PROXY ${COUNTRY_SECONDARY_GATEWAY_FX}:9443; DIRECT";
}
