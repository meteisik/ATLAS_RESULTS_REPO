import java.util.logging.Logger;

public class CWE117_P06_V2_SilentOrbitSafe {
    private static int privateFive = 5;

    public void handleSilentOrbit() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SILENT_ORBIT_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentOrbitSafeSink()).logSilentOrbit(data);
    }
}

class CWE117_P06_V2_SilentOrbitSafeSink {
    public void logSilentOrbit(String data) {
        Logger silentOrbitLogger = Logger.getLogger("silentOrbit.audit");
        silentOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
