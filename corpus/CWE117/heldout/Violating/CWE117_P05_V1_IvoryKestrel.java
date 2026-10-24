import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryKestrel {

    private String ivoryKestrelData;

    private void logIvoryKestrel() {
        String data = ivoryKestrelData;
        Logger ivoryKestrelLogger = Logger.getLogger("ivoryKestrel.audit");
        ivoryKestrelLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryKestrel() {
        String data;
        data = System.getenv("IVORY_KESTREL_USER");
        ivoryKestrelData = data;
        logIvoryKestrel();
    }
}
