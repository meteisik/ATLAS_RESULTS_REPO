import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryHelix {

    private String ivoryHelixData;

    private void logIvoryHelix() {
        String data = ivoryHelixData;
        Logger ivoryHelixLogger = Logger.getLogger("ivoryHelix.audit");
        ivoryHelixLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryHelix() {
        String data;
        data = System.getenv("IVORY_HELIX_USER");
        ivoryHelixData = data;
        logIvoryHelix();
    }
}
