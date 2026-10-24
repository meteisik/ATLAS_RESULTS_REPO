import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryHelix {

    private String readIvoryHelix() {
        String data;
        data = System.getenv("IVORY_HELIX_USER");
        return data;
    }

    public void handleIvoryHelix() {
        String data = readIvoryHelix();
        Logger ivoryHelixLogger = Logger.getLogger("ivoryHelix.audit");
        ivoryHelixLogger.info("Login attempt for user " + data);
    }
}
