import java.util.logging.Logger;

public class CWE117_P02_V2_NovaAuroraSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleNovaAurora() {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = System.getenv("NOVA_AURORA_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger novaAuroraLogger = Logger.getLogger("novaAurora.audit");
            novaAuroraLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
