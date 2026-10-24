import java.util.logging.Logger;

public class CWE117_P04_V1_JadePrism {

    private String readJadePrism() {
        String data;
        data = System.getenv("JADE_PRISM_USER");
        return data;
    }

    public void handleJadePrism() {
        String data = readJadePrism();
        Logger jadePrismLogger = Logger.getLogger("jadePrism.audit");
        jadePrismLogger.info("Login attempt for user " + data);
    }
}
