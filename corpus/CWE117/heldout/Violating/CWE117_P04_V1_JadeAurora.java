import java.util.logging.Logger;

public class CWE117_P04_V1_JadeAurora {

    private String readJadeAurora() {
        String data;
        data = System.getenv("JADE_AURORA_USER");
        return data;
    }

    public void handleJadeAurora() {
        String data = readJadeAurora();
        Logger jadeAuroraLogger = Logger.getLogger("jadeAurora.audit");
        jadeAuroraLogger.info("Login attempt for user " + data);
    }
}
