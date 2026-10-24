import java.util.logging.Logger;

public class CWE117_P05_V2_SaffronCascade {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String saffronCascadeData;

    private void logSaffronCascade() {
        String data = saffronCascadeData;
        Logger saffronCascadeLogger = Logger.getLogger("saffronCascade.audit");
        saffronCascadeLogger.info("Login attempt for user " + data);
    }

    public void handleSaffronCascade() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SAFFRON_CASCADE_USER");
        } else {
            data = null;
        }
        saffronCascadeData = data;
        logSaffronCascade();
    }
}
