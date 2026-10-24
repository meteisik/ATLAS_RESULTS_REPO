import java.util.logging.Logger;

public class CWE117_P02_V2_IvoryHelix {
    private static boolean privateReturnsTrue() { return true; }

    public void handleIvoryHelix() {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = System.getenv("IVORY_HELIX_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger ivoryHelixLogger = Logger.getLogger("ivoryHelix.audit");
            ivoryHelixLogger.info("Login attempt for user " + data);
        }
    }
}
