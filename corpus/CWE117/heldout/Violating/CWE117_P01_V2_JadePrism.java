import java.util.logging.Logger;

public class CWE117_P01_V2_JadePrism {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleJadePrism() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("JADE_PRISM_USER");
        } else {
            data = null;
        }
        Logger jadePrismLogger = Logger.getLogger("jadePrism.audit");
        jadePrismLogger.info("Login attempt for user " + data);
    }
}
