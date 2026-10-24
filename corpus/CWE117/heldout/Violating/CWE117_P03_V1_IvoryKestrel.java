import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryKestrel {

    private void logIvoryKestrel(String data) {
        Logger ivoryKestrelLogger = Logger.getLogger("ivoryKestrel.audit");
        ivoryKestrelLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryKestrel() {
        String data;
        data = System.getenv("IVORY_KESTREL_USER");
        logIvoryKestrel(data);
    }
}
