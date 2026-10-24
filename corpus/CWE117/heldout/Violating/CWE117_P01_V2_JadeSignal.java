import java.util.logging.Logger;

public class CWE117_P01_V2_JadeSignal {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleJadeSignal() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("JADE_SIGNAL_USER");
        } else {
            data = null;
        }
        Logger jadeSignalLogger = Logger.getLogger("jadeSignal.audit");
        jadeSignalLogger.info("Login attempt for user " + data);
    }
}
