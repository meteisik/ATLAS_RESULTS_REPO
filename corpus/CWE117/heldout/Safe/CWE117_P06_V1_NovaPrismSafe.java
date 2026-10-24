import java.util.logging.Logger;

public class CWE117_P06_V1_NovaPrismSafe {

    public void handleNovaPrism() {
        String data;
        data = System.getenv("NOVA_PRISM_USER");
        (new CWE117_P06_V1_NovaPrismSafeSink()).logNovaPrism(data);
    }
}

class CWE117_P06_V1_NovaPrismSafeSink {
    public void logNovaPrism(String data) {
        Logger novaPrismLogger = Logger.getLogger("novaPrism.audit");
        novaPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
