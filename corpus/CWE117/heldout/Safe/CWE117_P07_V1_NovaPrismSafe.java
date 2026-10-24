import java.util.logging.Logger;

public class CWE117_P07_V1_NovaPrismSafe {

    public void handleNovaPrism() {
        String data;
        data = (new CWE117_P07_V1_NovaPrismSafeSource()).readNovaPrism();
        Logger novaPrismLogger = Logger.getLogger("novaPrism.audit");
        novaPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_NovaPrismSafeSource {
    public String readNovaPrism() {
        String data;
        data = System.getenv("NOVA_PRISM_USER");
        return data;
    }
}
