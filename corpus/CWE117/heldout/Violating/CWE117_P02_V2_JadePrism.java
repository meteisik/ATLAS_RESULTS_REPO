import java.util.logging.Logger;

public class CWE117_P02_V2_JadePrism {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleJadePrism() {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_FIVE == 5) {
                data = System.getenv("JADE_PRISM_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger jadePrismLogger = Logger.getLogger("jadePrism.audit");
            jadePrismLogger.info("Login attempt for user " + data);
        }
    }
}
