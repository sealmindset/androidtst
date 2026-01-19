// Frida SSL Pinning Bypass for SleepIQ
// Disables certificate pinning and TrustManager validation

Java.perform(function() {
    console.log("[*] Starting SSL Pinning Bypass...");

    // Disable TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Bypassing TrustManagerImpl.verifyChain for: ' + host);
            return untrustedChain;
        };
    } catch(e) {
        console.log('[-] TrustManagerImpl.verifyChain not found: ' + e);
    }

    // Disable SSLContext
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManager, trustManager, secureRandom) {
            console.log('[+] Bypassing SSLContext.init()');
            var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var EmptyTrustManager = Java.registerClass({
                name: 'com.frida.EmptyTrustManager',
                implements: [TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            var tm = EmptyTrustManager.$new();
            return this.init(keyManager, [tm], secureRandom);
        };
    } catch(e) {
        console.log('[-] SSLContext.init not hooked: ' + e);
    }

    // OkHttp CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] Bypassing OkHttp CertificatePinner.check for: ' + hostname);
            return;
        };
        CertificatePinner.check$okhttp.implementation = function(hostname, fn) {
            console.log('[+] Bypassing OkHttp CertificatePinner.check$okhttp for: ' + hostname);
            return;
        };
    } catch(e) {
        console.log('[-] OkHttp CertificatePinner not found: ' + e);
    }

    // Mixpanel specific - check for custom SSL
    try {
        var classes = Java.enumerateLoadedClassesSync();
        classes.forEach(function(className) {
            if (className.includes('mixpanel') && className.toLowerCase().includes('ssl')) {
                console.log('[*] Found Mixpanel SSL class: ' + className);
            }
        });
    } catch(e) {}

    console.log("[*] SSL Pinning Bypass Complete!");
});
