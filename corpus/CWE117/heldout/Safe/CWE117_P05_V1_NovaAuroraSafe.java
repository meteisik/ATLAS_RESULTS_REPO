import java.util.logging.Logger;

public class CWE117_P05_V1_NovaAuroraSafe {

    private String novaAuroraData;

    private void logNovaAurora() {
        String data = novaAuroraData;
        Logger novaAuroraLogger = Logger.getLogger("novaAurora.audit");
        novaAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleNovaAurora() {
        String data;
        data = System.getenv("NOVA_AURORA_USER");
        novaAuroraData = data;
        logNovaAurora();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
