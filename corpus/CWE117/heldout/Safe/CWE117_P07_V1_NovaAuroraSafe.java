import java.util.logging.Logger;

public class CWE117_P07_V1_NovaAuroraSafe {

    public void handleNovaAurora() {
        String data;
        data = (new CWE117_P07_V1_NovaAuroraSafeSource()).readNovaAurora();
        Logger novaAuroraLogger = Logger.getLogger("novaAurora.audit");
        novaAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_NovaAuroraSafeSource {
    public String readNovaAurora() {
        String data;
        data = System.getenv("NOVA_AURORA_USER");
        return data;
    }
}
