import java.util.logging.Logger;

public class CWE117_P03_V2_JadePrism {
    private static boolean privateReturnsTrue() { return true; }

    private void logJadePrism(String data) {
        Logger jadePrismLogger = Logger.getLogger("jadePrism.audit");
        jadePrismLogger.info("Login attempt for user " + data);
    }

    public void handleJadePrism() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("JADE_PRISM_USER");
        } else {
            data = null;
        }
        logJadePrism(data);
    }
}
