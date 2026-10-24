import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryKestrel {

    private String readIvoryKestrel() {
        String data;
        data = System.getenv("IVORY_KESTREL_USER");
        return data;
    }

    public void handleIvoryKestrel() {
        String data = readIvoryKestrel();
        Logger ivoryKestrelLogger = Logger.getLogger("ivoryKestrel.audit");
        ivoryKestrelLogger.info("Login attempt for user " + data);
    }
}
