// Frida Root Detection Bypass
// Hooks common root detection methods to hide rooted device status
//
// Usage: frida -U -l frida_root_bypass.js -f <package>
//        frida -U -l frida_root_bypass.js --no-pause -f <package>

Java.perform(function() {
    console.log("[*] Starting Root Detection Bypass...");

    // Common root-related paths to hide
    var rootPaths = [
        "/system/app/Superuser.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/su/bin/su",
        "/magisk",
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock",
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/sbin/busybox",
        "/data/local/xbin/busybox"
    ];

    // Root management app packages to hide
    var rootPackages = [
        "com.topjohnwu.magisk",
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot"
    ];

    // Hook File.exists() to hide root paths
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++) {
                if (path.indexOf(rootPaths[i]) !== -1) {
                    console.log('[+] File.exists() blocked for: ' + path);
                    return false;
                }
            }
            return this.exists();
        };
        console.log('[+] Hooked File.exists()');
    } catch(e) {
        console.log('[-] File.exists() hook error: ' + e);
    }

    // Hook Runtime.exec() to block su/which su commands
    try {
        var Runtime = Java.use('java.lang.Runtime');

        // Hook exec(String)
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 ||
                cmd.indexOf('busybox') !== -1 || cmd.indexOf('magisk') !== -1) {
                console.log('[+] Runtime.exec() blocked: ' + cmd);
                throw Java.use('java.io.IOException').$new('Permission denied');
            }
            return this.exec(cmd);
        };

        // Hook exec(String[])
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
            var cmd = cmdArray.join(' ');
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 ||
                cmd.indexOf('busybox') !== -1 || cmd.indexOf('magisk') !== -1) {
                console.log('[+] Runtime.exec() blocked: ' + cmd);
                throw Java.use('java.io.IOException').$new('Permission denied');
            }
            return this.exec(cmdArray);
        };
        console.log('[+] Hooked Runtime.exec()');
    } catch(e) {
        console.log('[-] Runtime.exec() hook error: ' + e);
    }

    // Hook ProcessBuilder to block root-checking processes
    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function() {
            var cmd = this.command().toString();
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 ||
                cmd.indexOf('busybox') !== -1 || cmd.indexOf('magisk') !== -1) {
                console.log('[+] ProcessBuilder.start() blocked: ' + cmd);
                throw Java.use('java.io.IOException').$new('Permission denied');
            }
            return this.start();
        };
        console.log('[+] Hooked ProcessBuilder.start()');
    } catch(e) {
        console.log('[-] ProcessBuilder.start() hook error: ' + e);
    }

    // Hook Build.TAGS to return release-keys
    try {
        var Build = Java.use('android.os.Build');
        var buildTagsField = Build.class.getDeclaredField('TAGS');
        buildTagsField.setAccessible(true);
        buildTagsField.set(null, 'release-keys');
        console.log('[+] Set Build.TAGS to release-keys');
    } catch(e) {
        console.log('[-] Build.TAGS modification error: ' + e);
    }

    // Hook System.getProperty() to return safe values
    try {
        var System = Java.use('java.lang.System');
        System.getProperty.overload('java.lang.String').implementation = function(prop) {
            if (prop === 'ro.debuggable') {
                console.log('[+] System.getProperty() returning 0 for ro.debuggable');
                return '0';
            }
            if (prop === 'ro.secure') {
                console.log('[+] System.getProperty() returning 1 for ro.secure');
                return '1';
            }
            if (prop === 'ro.build.selinux') {
                console.log('[+] System.getProperty() returning 1 for ro.build.selinux');
                return '1';
            }
            return this.getProperty(prop);
        };
        console.log('[+] Hooked System.getProperty()');
    } catch(e) {
        console.log('[-] System.getProperty() hook error: ' + e);
    }

    // Hook PackageManager.getPackageInfo() to hide root apps
    try {
        var PackageManager = Java.use('android.app.ApplicationPackageManager');
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (packageName === rootPackages[i]) {
                    console.log('[+] PackageManager.getPackageInfo() hiding: ' + packageName);
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(packageName);
                }
            }
            return this.getPackageInfo(packageName, flags);
        };
        console.log('[+] Hooked PackageManager.getPackageInfo()');
    } catch(e) {
        console.log('[-] PackageManager.getPackageInfo() hook error: ' + e);
    }

    // Hook native system() calls via libc (for native root checks)
    try {
        var libc = Module.findExportByName('libc.so', 'system');
        if (libc) {
            Interceptor.attach(libc, {
                onEnter: function(args) {
                    var cmd = Memory.readUtf8String(args[0]);
                    if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1)) {
                        console.log('[+] Native system() blocked: ' + cmd);
                        args[0] = Memory.allocUtf8String('echo');
                    }
                }
            });
            console.log('[+] Hooked native system()');
        }
    } catch(e) {
        console.log('[-] Native system() hook error: ' + e);
    }

    // Hook native access() calls to hide root files
    try {
        var access = Module.findExportByName('libc.so', 'access');
        if (access) {
            Interceptor.attach(access, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    if (path) {
                        for (var i = 0; i < rootPaths.length; i++) {
                            if (path.indexOf(rootPaths[i]) !== -1) {
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

    // Hook RootBeer library if present
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[+] RootBeer.isRooted() returning false');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log('[+] RootBeer.isRootedWithoutBusyBoxCheck() returning false');
            return false;
        };
        console.log('[+] Hooked RootBeer library');
    } catch(e) {
        console.log('[-] RootBeer not found (app may not use it): ' + e.message);
    }

    console.log("[*] Root Detection Bypass Complete!");
});
