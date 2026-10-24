import java.util.logging.Logger;

public class CWE117_P06_V1_NovaCascadeSafe {

    public void handleNovaCascade() {
        String data;
        data = System.getenv("NOVA_CASCADE_USER");
        (new CWE117_P06_V1_NovaCascadeSafeSink()).logNovaCascade(data);
    }
}

class CWE117_P06_V1_NovaCascadeSafeSink {
    public void logNovaCascade(String data) {
        Logger novaCascadeLogger = Logger.getLogger("novaCascade.audit");
        novaCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
