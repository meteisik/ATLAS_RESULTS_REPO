import java.util.logging.Logger;

public class CWE117_P10_V2_AmberPrism {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public void handleAmberPrism() {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AMBER_PRISM_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberPrismSink()).logAmberPrism();
    }
}

class CWE117_P10_V2_AmberPrismSink {
    public void logAmberPrism() {
        String data = CWE117_P10_V2_AmberPrism.data;
        Logger amberPrismLogger = Logger.getLogger("amberPrism.audit");
        amberPrismLogger.info("Login attempt for user " + data);
    }
}
