import java.util.logging.Logger;

public class CWE117_P07_V1_NovaCascadeSafe {

    public void handleNovaCascade() {
        String data;
        data = (new CWE117_P07_V1_NovaCascadeSafeSource()).readNovaCascade();
        Logger novaCascadeLogger = Logger.getLogger("novaCascade.audit");
        novaCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_NovaCascadeSafeSource {
    public String readNovaCascade() {
        String data;
        data = System.getenv("NOVA_CASCADE_USER");
        return data;
    }
}
