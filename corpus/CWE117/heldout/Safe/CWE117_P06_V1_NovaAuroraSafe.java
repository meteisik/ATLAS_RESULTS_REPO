import java.util.logging.Logger;

public class CWE117_P06_V1_NovaAuroraSafe {

    public void handleNovaAurora() {
        String data;
        data = System.getenv("NOVA_AURORA_USER");
        (new CWE117_P06_V1_NovaAuroraSafeSink()).logNovaAurora(data);
    }
}

class CWE117_P06_V1_NovaAuroraSafeSink {
    public void logNovaAurora(String data) {
        Logger novaAuroraLogger = Logger.getLogger("novaAurora.audit");
        novaAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
