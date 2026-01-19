// Frida Emulator Detection Bypass
// Hooks common emulator detection methods to hide emulator environment
//
// Usage: frida -U -l frida_emulator_bypass.js -f <package>
//        frida -U -l frida_emulator_bypass.js --no-pause -f <package>
//
// Combine with root bypass:
//        frida -U -l frida_root_bypass.js -l frida_emulator_bypass.js -f <package>

Java.perform(function() {
    console.log("[*] Starting Emulator Detection Bypass...");

    // Fake device values to spoof (Pixel 6 Pro)
    var fakeDevice = {
        FINGERPRINT: "google/raven/raven:12/SQ1A.211205.008/7888514:user/release-keys",
        MODEL: "Pixel 6 Pro",
        MANUFACTURER: "Google",
        BRAND: "google",
        DEVICE: "raven",
        PRODUCT: "raven",
        HARDWARE: "raven",
        BOARD: "raven",
        BOOTLOADER: "slider-1.0-7683913",
        HOST: "abfarm-release-rbe-2021-12-14_16-55-00-8014028350266668659",
        ID: "SQ1A.211205.008",
        DISPLAY: "SQ1A.211205.008",
        SERIAL: "unknown"
    };

    // Emulator-specific files to hide
    var emulatorFiles = [
        "/dev/qemu_pipe",
        "/dev/goldfish_pipe",
        "/dev/socket/qemud",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/system/bin/qemud",
        "/system/lib/egl/libEGL_emulation.so",
        "/system/lib/egl/libGLESv1_CM_emulation.so",
        "/system/lib/egl/libGLESv2_emulation.so",
        "/init.goldfish.rc",
        "/init.ranchu.rc",
        "/system/etc/init.goldfish.sh",
        "/proc/tty/drivers"
    ];

    // Emulator-related strings to detect in various checks
    var emulatorStrings = [
        "goldfish", "ranchu", "generic", "sdk", "google_sdk",
        "vbox", "genymotion", "android sdk built for x86"
    ];

    // Modify Build class fields
    try {
        var Build = Java.use('android.os.Build');

        // Set FINGERPRINT
        var fingerprintField = Build.class.getDeclaredField('FINGERPRINT');
        fingerprintField.setAccessible(true);
        fingerprintField.set(null, fakeDevice.FINGERPRINT);
        console.log('[+] Set Build.FINGERPRINT');

        // Set MODEL
        var modelField = Build.class.getDeclaredField('MODEL');
        modelField.setAccessible(true);
        modelField.set(null, fakeDevice.MODEL);
        console.log('[+] Set Build.MODEL');

        // Set MANUFACTURER
        var manufacturerField = Build.class.getDeclaredField('MANUFACTURER');
        manufacturerField.setAccessible(true);
        manufacturerField.set(null, fakeDevice.MANUFACTURER);
        console.log('[+] Set Build.MANUFACTURER');

        // Set BRAND
        var brandField = Build.class.getDeclaredField('BRAND');
        brandField.setAccessible(true);
        brandField.set(null, fakeDevice.BRAND);
        console.log('[+] Set Build.BRAND');

        // Set DEVICE
        var deviceField = Build.class.getDeclaredField('DEVICE');
        deviceField.setAccessible(true);
        deviceField.set(null, fakeDevice.DEVICE);
        console.log('[+] Set Build.DEVICE');

        // Set PRODUCT
        var productField = Build.class.getDeclaredField('PRODUCT');
        productField.setAccessible(true);
        productField.set(null, fakeDevice.PRODUCT);
        console.log('[+] Set Build.PRODUCT');

        // Set HARDWARE
        var hardwareField = Build.class.getDeclaredField('HARDWARE');
        hardwareField.setAccessible(true);
        hardwareField.set(null, fakeDevice.HARDWARE);
        console.log('[+] Set Build.HARDWARE');

        // Set BOARD
        var boardField = Build.class.getDeclaredField('BOARD');
        boardField.setAccessible(true);
        boardField.set(null, fakeDevice.BOARD);
        console.log('[+] Set Build.BOARD');

        // Set SERIAL
        var serialField = Build.class.getDeclaredField('SERIAL');
        serialField.setAccessible(true);
        serialField.set(null, fakeDevice.SERIAL);
        console.log('[+] Set Build.SERIAL');

        // Set ID
        var idField = Build.class.getDeclaredField('ID');
        idField.setAccessible(true);
        idField.set(null, fakeDevice.ID);
        console.log('[+] Set Build.ID');

    } catch(e) {
        console.log('[-] Build field modification error: ' + e);
    }

    // Hook TelephonyManager methods
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');

        // getDeviceId - return fake IMEI
        TelephonyManager.getDeviceId.overload().implementation = function() {
            console.log('[+] TelephonyManager.getDeviceId() returning fake IMEI');
            return '358240051111110';
        };

        // getDeviceId with slot
        try {
            TelephonyManager.getDeviceId.overload('int').implementation = function(slot) {
                console.log('[+] TelephonyManager.getDeviceId(slot) returning fake IMEI');
                return '358240051111110';
            };
        } catch(e) {}

        // getSubscriberId - return fake IMSI
        TelephonyManager.getSubscriberId.overload().implementation = function() {
            console.log('[+] TelephonyManager.getSubscriberId() returning fake IMSI');
            return '310260000000000';
        };

        // getLine1Number - return fake phone number
        TelephonyManager.getLine1Number.overload().implementation = function() {
            console.log('[+] TelephonyManager.getLine1Number() returning fake number');
            return '+14155551234';
        };

        // getNetworkOperatorName - return carrier name
        TelephonyManager.getNetworkOperatorName.overload().implementation = function() {
            console.log('[+] TelephonyManager.getNetworkOperatorName() returning T-Mobile');
            return 'T-Mobile';
        };

        // getNetworkOperator - return carrier MCC+MNC
        TelephonyManager.getNetworkOperator.overload().implementation = function() {
            console.log('[+] TelephonyManager.getNetworkOperator() returning 310260');
            return '310260';
        };

        // getSimOperatorName
        TelephonyManager.getSimOperatorName.overload().implementation = function() {
            console.log('[+] TelephonyManager.getSimOperatorName() returning T-Mobile');
            return 'T-Mobile';
        };

        // getSimOperator
        TelephonyManager.getSimOperator.overload().implementation = function() {
            console.log('[+] TelephonyManager.getSimOperator() returning 310260');
            return '310260';
        };

        // getSimCountryIso
        TelephonyManager.getSimCountryIso.overload().implementation = function() {
            return 'us';
        };

        // getNetworkCountryIso
        TelephonyManager.getNetworkCountryIso.overload().implementation = function() {
            return 'us';
        };

        // getPhoneType
        TelephonyManager.getPhoneType.overload().implementation = function() {
            return 1; // PHONE_TYPE_GSM
        };

        console.log('[+] Hooked TelephonyManager methods');
    } catch(e) {
        console.log('[-] TelephonyManager hook error: ' + e);
    }

    // Hook File.exists() to hide emulator files
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < emulatorFiles.length; i++) {
                if (path.indexOf(emulatorFiles[i]) !== -1) {
                    console.log('[+] File.exists() hiding emulator file: ' + path);
                    return false;
                }
            }
            return this.exists();
        };
        console.log('[+] Hooked File.exists() for emulator files');
    } catch(e) {
        console.log('[-] File.exists() hook error: ' + e);
    }

    // Hook System.getProperty() to hide emulator properties
    try {
        var System = Java.use('java.lang.System');
        System.getProperty.overload('java.lang.String').implementation = function(prop) {
            var result = this.getProperty(prop);

            // Hide emulator-specific properties
            if (prop === 'ro.kernel.qemu' || prop === 'ro.kernel.android.qemud') {
                console.log('[+] System.getProperty() hiding: ' + prop);
                return null;
            }
            if (prop === 'ro.hardware') {
                console.log('[+] System.getProperty() spoofing ro.hardware');
                return fakeDevice.HARDWARE;
            }
            if (prop === 'ro.product.model') {
                console.log('[+] System.getProperty() spoofing ro.product.model');
                return fakeDevice.MODEL;
            }
            if (prop === 'ro.product.brand') {
                return fakeDevice.BRAND;
            }
            if (prop === 'ro.product.device') {
                return fakeDevice.DEVICE;
            }
            if (prop === 'ro.product.manufacturer') {
                return fakeDevice.MANUFACTURER;
            }
            if (prop === 'ro.build.fingerprint') {
                return fakeDevice.FINGERPRINT;
            }

            // Check if result contains emulator indicators
            if (result !== null) {
                var lowerResult = result.toLowerCase();
                for (var i = 0; i < emulatorStrings.length; i++) {
                    if (lowerResult.indexOf(emulatorStrings[i]) !== -1) {
                        console.log('[+] System.getProperty() blocking emulator value for: ' + prop);
                        return null;
                    }
                }
            }
            return result;
        };
        console.log('[+] Hooked System.getProperty()');
    } catch(e) {
        console.log('[-] System.getProperty() hook error: ' + e);
    }

    // Hook SensorManager to fake sensor availability
    try {
        var SensorManager = Java.use('android.hardware.SensorManager');
        var Sensor = Java.use('android.hardware.Sensor');

        // Hook getSensorList to return non-empty lists
        SensorManager.getSensorList.overload('int').implementation = function(type) {
            var result = this.getSensorList(type);
            if (result.size() === 0) {
                console.log('[+] SensorManager.getSensorList() - sensor type ' + type + ' empty, faking presence');
                // Return original empty list - detection should use other methods
            }
            return result;
        };
        console.log('[+] Hooked SensorManager');
    } catch(e) {
        console.log('[-] SensorManager hook error: ' + e);
    }

    // Hook native system property reads
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            var result = this.get(key);
            if (key === 'ro.kernel.qemu' || key === 'ro.kernel.android.qemud') {
                console.log('[+] SystemProperties.get() hiding: ' + key);
                return '';
            }
            if (key === 'ro.hardware' || key === 'ro.product.hardware') {
                return fakeDevice.HARDWARE;
            }
            if (key === 'ro.product.model') {
                return fakeDevice.MODEL;
            }
            if (key === 'ro.product.brand') {
                return fakeDevice.BRAND;
            }
            if (key === 'ro.build.fingerprint') {
                return fakeDevice.FINGERPRINT;
            }
            // Check for emulator strings in result
            if (result !== null && result !== '') {
                var lowerResult = result.toLowerCase();
                for (var i = 0; i < emulatorStrings.length; i++) {
                    if (lowerResult.indexOf(emulatorStrings[i]) !== -1) {
                        console.log('[+] SystemProperties.get() blocking emulator value for: ' + key);
                        return '';
                    }
                }
            }
            return result;
        };

        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            var result = this.get(key, def);
            if (key === 'ro.kernel.qemu' || key === 'ro.kernel.android.qemud') {
                console.log('[+] SystemProperties.get() hiding: ' + key);
                return def;
            }
            if (key === 'ro.hardware' || key === 'ro.product.hardware') {
                return fakeDevice.HARDWARE;
            }
            // Check for emulator strings
            if (result !== null && result !== def) {
                var lowerResult = result.toLowerCase();
                for (var i = 0; i < emulatorStrings.length; i++) {
                    if (lowerResult.indexOf(emulatorStrings[i]) !== -1) {
                        return def;
                    }
                }
            }
            return result;
        };
        console.log('[+] Hooked SystemProperties');
    } catch(e) {
        console.log('[-] SystemProperties hook error: ' + e);
    }

    // Hook native file operations
    try {
        var fopen = Module.findExportByName('libc.so', 'fopen');
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    if (path) {
                        // Block access to /proc/cpuinfo for goldfish/ranchu detection
                        if (path === '/proc/cpuinfo') {
                            this.isCpuinfo = true;
                        }
                        // Block emulator-specific files
                        for (var i = 0; i < emulatorFiles.length; i++) {
                            if (path.indexOf(emulatorFiles[i]) !== -1) {
                                console.log('[+] Native fopen() blocked: ' + path);
                                args[0] = Memory.allocUtf8String('/dev/null');
                                return;
                            }
                        }
                    }
                }
            });
            console.log('[+] Hooked native fopen()');
        }
    } catch(e) {
        console.log('[-] Native fopen() hook error: ' + e);
    }

    // Hook native access() to hide emulator files
    try {
        var access = Module.findExportByName('libc.so', 'access');
        if (access) {
            Interceptor.attach(access, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    if (path) {
                        for (var i = 0; i < emulatorFiles.length; i++) {
                            if (path.indexOf(emulatorFiles[i]) !== -1) {
                                console.log('[+] Native access() blocked for: ' + path);
                                this.blocked = true;
                                return;
                            }
                        }
                    }
                    this.blocked = false;
                },
                onLeave: function(retval) {
                    if (this.blocked) {
                        retval.replace(-1);
                    }
                }
            });
            console.log('[+] Hooked native access()');
        }
    } catch(e) {
        console.log('[-] Native access() hook error: ' + e);
    }

    console.log("[*] Emulator Detection Bypass Complete!");
});
