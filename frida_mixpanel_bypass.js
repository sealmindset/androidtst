// Frida SSL Pinning Bypass - Targeting Mixpanel SDK
// Hooks SSLContext initialization and HttpURLConnection

Java.perform(function() {
    console.log("[*] Starting Mixpanel-targeted SSL Pinning Bypass...");

    // Hook SSLContext.getInstance to return a permissive context
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        // Hook init with all overloads
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
            console.log('[+] SSLContext.init() called - injecting permissive TrustManager');

            var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var PermissiveTrustManager = Java.registerClass({
                name: 'com.frida.PermissiveTrustManager' + Math.random().toString(36).substr(2),
                implements: [TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {
                        console.log('[+] checkClientTrusted bypassed');
                    },
                    checkServerTrusted: function(chain, authType) {
                        console.log('[+] checkServerTrusted bypassed');
                    },
                    getAcceptedIssuers: function() {
                        return [];
                    }
                }
            });

            var permissiveTM = PermissiveTrustManager.$new();
            return this.init(km, [permissiveTM], sr);
        };
    } catch(e) {
        console.log('[-] SSLContext hook error: ' + e);
    }

    // Hook TrustManagerImpl for Android's implementation
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl.verifyChain bypassed for: ' + host);
            return untrustedChain;
        };

        TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
            console.log('[+] TrustManagerImpl.checkTrustedRecursive bypassed for: ' + host);
            return Java.use('java.util.ArrayList').$new();
        };
    } catch(e) {
        console.log('[-] TrustManagerImpl hook error: ' + e);
    }

    // Hook HttpsURLConnection to accept all certificates
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setSSLSocketFactory.implementation = function(factory) {
            console.log('[+] HttpsURLConnection.setSSLSocketFactory called');
            return this.setSSLSocketFactory(factory);
        };

        HttpsURLConnection.setHostnameVerifier.implementation = function(verifier) {
            console.log('[+] HttpsURLConnection.setHostnameVerifier - setting permissive');
            var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
            var PermissiveHostnameVerifier = Java.registerClass({
                name: 'com.frida.PermissiveHostnameVerifier',
                implements: [HostnameVerifier],
                methods: {
                    verify: function(hostname, session) {
                        console.log('[+] HostnameVerifier.verify bypassed for: ' + hostname);
                        return true;
                    }
                }
            });
            return this.setHostnameVerifier(PermissiveHostnameVerifier.$new());
        };
    } catch(e) {
        console.log('[-] HttpsURLConnection hook error: ' + e);
    }

    // Hook URL.openConnection to monitor Mixpanel traffic
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            var url = this.toString();
            if (url.indexOf('mixpanel') !== -1) {
                console.log('[*] MIXPANEL REQUEST: ' + url);
            }
            return this.openConnection();
        };
    } catch(e) {
        console.log('[-] URL.openConnection hook error: ' + e);
    }

    // Monitor all HTTPS connections for mixpanel
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.setRequestProperty.implementation = function(key, value) {
            if (this.getURL().toString().indexOf('mixpanel') !== -1) {
                console.log('[*] Mixpanel header: ' + key + ' = ' + value);
            }
            return this.setRequestProperty(key, value);
        };

        HttpURLConnection.getOutputStream.implementation = function() {
            var url = this.getURL().toString();
            if (url.indexOf('mixpanel') !== -1) {
                console.log('[*] Mixpanel getOutputStream: ' + url);
            }
            return this.getOutputStream();
        };
    } catch(e) {
        console.log('[-] HttpURLConnection hook error: ' + e);
    }

    // Hook Mixpanel config class directly
    try {
        var MPConfig = Java.use('Fd.c');
        MPConfig.b.implementation = function() {
            console.log('[*] MPConfig.b() called - returning null SSLSocketFactory');
            // Return null to use default system factory (which we've hooked)
            return null;
        };
    } catch(e) {
        console.log('[-] MPConfig hook error: ' + e);
    }

    console.log("[*] Mixpanel SSL Pinning Bypass Complete!");
});
