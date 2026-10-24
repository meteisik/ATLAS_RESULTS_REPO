import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryLantern {

    private String readIvoryLantern() {
        String data;
        data = System.getenv("IVORY_LANTERN_USER");
        return data;
    }

    public void handleIvoryLantern() {
        String data = readIvoryLantern();
        Logger ivoryLanternLogger = Logger.getLogger("ivoryLantern.audit");
        ivoryLanternLogger.info("Login attempt for user " + data);
    }
}
