import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryLantern {

    private void logIvoryLantern(String data) {
        Logger ivoryLanternLogger = Logger.getLogger("ivoryLantern.audit");
        ivoryLanternLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryLantern() {
        String data;
        data = System.getenv("IVORY_LANTERN_USER");
        logIvoryLantern(data);
    }
}
