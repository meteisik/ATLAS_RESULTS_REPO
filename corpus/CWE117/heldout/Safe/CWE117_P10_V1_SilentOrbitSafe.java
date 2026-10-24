import java.util.logging.Logger;

public class CWE117_P10_V1_SilentOrbitSafe {

    public static String data;

    public void handleSilentOrbit() {
        data = System.getenv("SILENT_ORBIT_USER");
        (new CWE117_P10_V1_SilentOrbitSafeSink()).logSilentOrbit();
    }
}

class CWE117_P10_V1_SilentOrbitSafeSink {
    public void logSilentOrbit() {
        String data = CWE117_P10_V1_SilentOrbitSafe.data;
        Logger silentOrbitLogger = Logger.getLogger("silentOrbit.audit");
        silentOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
