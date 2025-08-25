setImmediate(function() {
    if (typeof Java === 'undefined') {
        console.log("[DIAGNOSTIC] Java is UNDEFINED at top-level. This is a critical error for Frida's Java API.");
    } else {
        console.log("[DIAGNOSTIC] Java is defined as: " + typeof Java);
    }
    Java.perform(function() {
        console.log("[DIAGNOSTIC] Inside Java.perform callback. typeof Java: " + typeof Java);
        try {
            var String = Java.use('java.lang.String');
            console.log("[DIAGNOSTIC] Successfully used Java.use('java.lang.String')!");
            // Optionally, create a string
            var myString = String.$new("Hello from Frida!");
            console.log("[DIAGNOSTIC] Created string: " + myString);
        } catch (e) {
            console.error("[DIAGNOSTIC] Error inside Java.perform trying to use Java: " + e.message);
            console.error("[DIAGNOSTIC] Stack: " + e.stack);
        }
    });
});