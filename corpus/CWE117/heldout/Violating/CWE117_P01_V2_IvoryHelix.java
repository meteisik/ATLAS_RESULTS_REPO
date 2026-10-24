import java.util.logging.Logger;

public class CWE117_P01_V2_IvoryHelix {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleIvoryHelix() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("IVORY_HELIX_USER");
        } else {
            data = null;
        }
        Logger ivoryHelixLogger = Logger.getLogger("ivoryHelix.audit");
        ivoryHelixLogger.info("Login attempt for user " + data);
    }
}
