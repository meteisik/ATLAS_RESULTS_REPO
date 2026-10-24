import java.util.logging.Logger;

public class CWE117_P06_V1_NovaAurora {

    public void handleNovaAurora() {
        String data;
        data = System.getenv("NOVA_AURORA_USER");
        (new CWE117_P06_V1_NovaAuroraSink()).logNovaAurora(data);
    }
}

class CWE117_P06_V1_NovaAuroraSink {
    public void logNovaAurora(String data) {
        Logger novaAuroraLogger = Logger.getLogger("novaAurora.audit");
        novaAuroraLogger.info("Login attempt for user " + data);
    }
}
