import java.util.logging.Logger;

public class CWE117_P05_V2_NovaPrism {

    private String novaPrismData;

    private void logNovaPrism() {
        String data = novaPrismData;
        Logger novaPrismLogger = Logger.getLogger("novaPrism.audit");
        novaPrismLogger.info("Login attempt for user " + data);
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
}
