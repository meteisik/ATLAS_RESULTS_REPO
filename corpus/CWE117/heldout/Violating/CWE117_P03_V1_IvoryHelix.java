import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryHelix {

    private void logIvoryHelix(String data) {
        Logger ivoryHelixLogger = Logger.getLogger("ivoryHelix.audit");
        ivoryHelixLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryHelix() {
        String data;
        data = System.getenv("IVORY_HELIX_USER");
        logIvoryHelix(data);
    }
}
