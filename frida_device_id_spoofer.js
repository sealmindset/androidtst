/**
 * Frida Device ID Spoofer
 *
 * Spoofs android_id and other device identifiers to make the device
 * appear as a different device to apps that enforce device limits.
 *
 * Usage:
 *   frida -U -f <package> -l frida_device_id_spoofer.js
 *
 * Configure SPOOFED_DEVICE_ID below or set dynamically.
 */

// Generate a random 16-character hex string (android_id format)
function generateRandomAndroidId() {
    var chars = '0123456789abcdef';
    var result = '';
    for (var i = 0; i < 16; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Configuration - set your custom ID or use random
// To use a specific ID, replace null with your ID string
var CUSTOM_DEVICE_ID = null;  // e.g., "abc123def456789a"
var SPOOFED_DEVICE_ID = CUSTOM_DEVICE_ID || generateRandomAndroidId();

console.log("[*] Device ID Spoofer loaded");
console.log("[*] Spoofed android_id: " + SPOOFED_DEVICE_ID);

Java.perform(function() {
    console.log("[*] Java environment ready");

    //=========================================================================
    // Hook 1: Settings.Secure.getString (primary android_id source)
    //=========================================================================
    try {
        var SettingsSecure = Java.use("android.provider.Settings$Secure");

        SettingsSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(resolver, name) {
            var result = this.getString(resolver, name);

            if (name === "android_id") {
                console.log("[+] Settings.Secure.getString(android_id)");
                console.log("    Original: " + result);
                console.log("    Spoofed:  " + SPOOFED_DEVICE_ID);
                return SPOOFED_DEVICE_ID;
            }

            return result;
        };
        console.log("[+] Hooked Settings.Secure.getString");
    } catch (e) {
        console.log("[-] Failed to hook Settings.Secure.getString: " + e);
    }

    //=========================================================================
    // Hook 2: TelephonyManager.getDeviceId (IMEI - older devices)
    //=========================================================================
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getDeviceId.overload().implementation = function() {
            console.log("[+] TelephonyManager.getDeviceId() -> spoofed");
            return "35" + SPOOFED_DEVICE_ID.substring(0, 13);  // IMEI format
        };

        TelephonyManager.getDeviceId.overload('int').implementation = function(slot) {
            console.log("[+] TelephonyManager.getDeviceId(slot) -> spoofed");
            return "35" + SPOOFED_DEVICE_ID.substring(0, 13);
        };
        console.log("[+] Hooked TelephonyManager.getDeviceId");
    } catch (e) {
        console.log("[-] Failed to hook TelephonyManager.getDeviceId: " + e);
    }

    //=========================================================================
    // Hook 3: TelephonyManager.getImei (Android 8+)
    //=========================================================================
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getImei.overload().implementation = function() {
            console.log("[+] TelephonyManager.getImei() -> spoofed");
            return "35" + SPOOFED_DEVICE_ID.substring(0, 13);
        };

        TelephonyManager.getImei.overload('int').implementation = function(slot) {
            console.log("[+] TelephonyManager.getImei(slot) -> spoofed");
            return "35" + SPOOFED_DEVICE_ID.substring(0, 13);
        };
        console.log("[+] Hooked TelephonyManager.getImei");
    } catch (e) {
        console.log("[-] TelephonyManager.getImei not available (expected on older Android)");
    }

    //=========================================================================
    // Hook 4: Build.SERIAL
    //=========================================================================
    try {
        var Build = Java.use("android.os.Build");
        var spoofedSerial = SPOOFED_DEVICE_ID.substring(0, 8).toUpperCase();

        Build.SERIAL.value = spoofedSerial;
        console.log("[+] Spoofed Build.SERIAL: " + spoofedSerial);
    } catch (e) {
        console.log("[-] Failed to spoof Build.SERIAL: " + e);
    }

    //=========================================================================
    // Hook 5: Build.getSerial() (Android 8+)
    //=========================================================================
    try {
        var Build = Java.use("android.os.Build");

        Build.getSerial.implementation = function() {
            var spoofed = SPOOFED_DEVICE_ID.substring(0, 8).toUpperCase();
            console.log("[+] Build.getSerial() -> " + spoofed);
            return spoofed;
        };
        console.log("[+] Hooked Build.getSerial");
    } catch (e) {
        console.log("[-] Build.getSerial not available (expected on older Android)");
    }

    //=========================================================================
    // Hook 6: TelephonyManager.getSubscriberId (IMSI)
    //=========================================================================
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getSubscriberId.overload().implementation = function() {
            var spoofed = "310260" + SPOOFED_DEVICE_ID.substring(0, 9);
            console.log("[+] TelephonyManager.getSubscriberId() -> " + spoofed);
            return spoofed;
        };
        console.log("[+] Hooked TelephonyManager.getSubscriberId");
    } catch (e) {
        console.log("[-] Failed to hook TelephonyManager.getSubscriberId: " + e);
    }

    //=========================================================================
    // Hook 7: TelephonyManager.getSimSerialNumber
    //=========================================================================
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getSimSerialNumber.overload().implementation = function() {
            var spoofed = "8901" + SPOOFED_DEVICE_ID.substring(0, 15);
            console.log("[+] TelephonyManager.getSimSerialNumber() -> " + spoofed);
            return spoofed;
        };
        console.log("[+] Hooked TelephonyManager.getSimSerialNumber");
    } catch (e) {
        console.log("[-] Failed to hook TelephonyManager.getSimSerialNumber: " + e);
    }

    //=========================================================================
    // Hook 8: WifiInfo.getMacAddress
    //=========================================================================
    try {
        var WifiInfo = Java.use("android.net.wifi.WifiInfo");

        WifiInfo.getMacAddress.implementation = function() {
            // Generate consistent MAC from device ID
            var mac = SPOOFED_DEVICE_ID.substring(0, 2) + ":" +
                      SPOOFED_DEVICE_ID.substring(2, 4) + ":" +
                      SPOOFED_DEVICE_ID.substring(4, 6) + ":" +
                      SPOOFED_DEVICE_ID.substring(6, 8) + ":" +
                      SPOOFED_DEVICE_ID.substring(8, 10) + ":" +
                      SPOOFED_DEVICE_ID.substring(10, 12);
            console.log("[+] WifiInfo.getMacAddress() -> " + mac.toUpperCase());
            return mac.toUpperCase();
        };
        console.log("[+] Hooked WifiInfo.getMacAddress");
    } catch (e) {
        console.log("[-] Failed to hook WifiInfo.getMacAddress: " + e);
    }

    //=========================================================================
    // Hook 9: BluetoothAdapter.getAddress (Bluetooth MAC)
    //=========================================================================
    try {
        var BluetoothAdapter = Java.use("android.bluetooth.BluetoothAdapter");

        BluetoothAdapter.getAddress.implementation = function() {
            var mac = SPOOFED_DEVICE_ID.substring(0, 2) + ":" +
                      SPOOFED_DEVICE_ID.substring(2, 4) + ":" +
                      SPOOFED_DEVICE_ID.substring(4, 6) + ":" +
                      SPOOFED_DEVICE_ID.substring(6, 8) + ":" +
                      SPOOFED_DEVICE_ID.substring(8, 10) + ":" +
                      SPOOFED_DEVICE_ID.substring(10, 12);
            console.log("[+] BluetoothAdapter.getAddress() -> " + mac.toUpperCase());
            return mac.toUpperCase();
        };
        console.log("[+] Hooked BluetoothAdapter.getAddress");
    } catch (e) {
        console.log("[-] Failed to hook BluetoothAdapter.getAddress: " + e);
    }

    //=========================================================================
    // Hook 10: UUID.randomUUID (if app generates unique IDs)
    // This is optional - only enable if the app uses UUID for device ID
    //=========================================================================
    /*
    try {
        var UUID = Java.use("java.util.UUID");
        var fixedUUID = Java.use("java.util.UUID").fromString(
            SPOOFED_DEVICE_ID.substring(0, 8) + "-" +
            SPOOFED_DEVICE_ID.substring(8, 12) + "-4" +
            SPOOFED_DEVICE_ID.substring(12, 15) + "-a" +
            SPOOFED_DEVICE_ID.substring(0, 3) + "-" +
            SPOOFED_DEVICE_ID.substring(0, 12)
        );

        UUID.randomUUID.implementation = function() {
            console.log("[+] UUID.randomUUID() -> fixed");
            return fixedUUID;
        };
        console.log("[+] Hooked UUID.randomUUID");
    } catch (e) {
        console.log("[-] Failed to hook UUID.randomUUID: " + e);
    }
    */

    //=========================================================================
    // Hook 11: SharedPreferences (intercept stored device IDs)
    //=========================================================================
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");

        SharedPreferencesImpl.getString.implementation = function(key, defValue) {
            var result = this.getString(key, defValue);

            // Check for common device ID keys
            var lowerKey = key.toLowerCase();
            if (lowerKey.indexOf("device") !== -1 ||
                lowerKey.indexOf("uuid") !== -1 ||
                lowerKey.indexOf("unique") !== -1 ||
                lowerKey.indexOf("android_id") !== -1) {
                console.log("[*] SharedPreferences.getString: " + key + " = " + result);
            }

            return result;
        };
        console.log("[+] Hooked SharedPreferences.getString (monitoring)");
    } catch (e) {
        console.log("[-] Failed to hook SharedPreferences: " + e);
    }

    //=========================================================================
    // Hook 12: react-native-device-info specific hooks
    //=========================================================================
    try {
        var RNDeviceModule = Java.use("com.learnium.RNDeviceInfo.RNDeviceModule");

        RNDeviceModule.getUniqueIdSync.implementation = function() {
            console.log("[+] RNDeviceModule.getUniqueIdSync() -> " + SPOOFED_DEVICE_ID);
            return SPOOFED_DEVICE_ID;
        };

        RNDeviceModule.getAndroidIdSync.implementation = function() {
            console.log("[+] RNDeviceModule.getAndroidIdSync() -> " + SPOOFED_DEVICE_ID);
            return SPOOFED_DEVICE_ID;
        };

        console.log("[+] Hooked RNDeviceModule (react-native-device-info)");
    } catch (e) {
        console.log("[-] RNDeviceModule not found (may not be React Native app): " + e);
    }

    console.log("\n[*] Device ID Spoofer initialized");
    console.log("[*] All device identifiers will now return spoofed values");
    console.log("[*] This device will appear as a different device to the app\n");
});
