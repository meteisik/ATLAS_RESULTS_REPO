import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryKestrelSafe {

    private String ivoryKestrelData;

    private void logIvoryKestrel() {
        String data = ivoryKestrelData;
        Logger ivoryKestrelLogger = Logger.getLogger("ivoryKestrel.audit");
        ivoryKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryKestrel() {
        String data;
        data = System.getenv("IVORY_KESTREL_USER");
        ivoryKestrelData = data;
        logIvoryKestrel();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
