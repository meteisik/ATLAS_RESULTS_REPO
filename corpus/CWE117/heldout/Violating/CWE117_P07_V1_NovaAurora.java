import java.util.logging.Logger;

public class CWE117_P07_V1_NovaAurora {

    public void handleNovaAurora() {
        String data;
        data = (new CWE117_P07_V1_NovaAuroraSource()).readNovaAurora();
        Logger novaAuroraLogger = Logger.getLogger("novaAurora.audit");
        novaAuroraLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_NovaAuroraSource {
    public String readNovaAurora() {
        String data;
        data = System.getenv("NOVA_AURORA_USER");
        return data;
    }
}
