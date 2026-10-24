import java.util.logging.Logger;

public class CWE117_P05_V2_NovaPrismSafe {

    private String novaPrismData;

    private void logNovaPrism() {
        String data = novaPrismData;
        Logger novaPrismLogger = Logger.getLogger("novaPrism.audit");
        novaPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleNovaPrism() {
        String data;
        if (5 == 5) {
            data = System.getenv("NOVA_PRISM_USER");
        } else {
            data = null;
        }
        novaPrismData = data;
        logNovaPrism();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
