import java.util.logging.Logger;

public class CWE117_P06_V2_SilentRavenSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleSilentRaven() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SILENT_RAVEN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentRavenSafeSink()).logSilentRaven(data);
    }
}

class CWE117_P06_V2_SilentRavenSafeSink {
    public void logSilentRaven(String data) {
        Logger silentRavenLogger = Logger.getLogger("silentRaven.audit");
        silentRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
