import java.util.logging.Logger;

public class CWE117_P05_V1_JadePrism {

    private String jadePrismData;

    private void logJadePrism() {
        String data = jadePrismData;
        Logger jadePrismLogger = Logger.getLogger("jadePrism.audit");
        jadePrismLogger.info("Login attempt for user " + data);
    }

    public void handleJadePrism() {
        String data;
        data = System.getenv("JADE_PRISM_USER");
        jadePrismData = data;
        logJadePrism();
    }
}
