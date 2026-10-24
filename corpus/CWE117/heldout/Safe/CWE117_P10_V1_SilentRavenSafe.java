import java.util.logging.Logger;

public class CWE117_P10_V1_SilentRavenSafe {

    public static String data;

    public void handleSilentRaven() {
        data = System.getenv("SILENT_RAVEN_USER");
        (new CWE117_P10_V1_SilentRavenSafeSink()).logSilentRaven();
    }
}

class CWE117_P10_V1_SilentRavenSafeSink {
    public void logSilentRaven() {
        String data = CWE117_P10_V1_SilentRavenSafe.data;
        Logger silentRavenLogger = Logger.getLogger("silentRaven.audit");
        silentRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
