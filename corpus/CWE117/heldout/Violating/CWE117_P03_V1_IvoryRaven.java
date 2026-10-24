import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryRaven {

    private void logIvoryRaven(String data) {
        Logger ivoryRavenLogger = Logger.getLogger("ivoryRaven.audit");
        ivoryRavenLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryRaven() {
        String data;
        data = System.getenv("IVORY_RAVEN_USER");
        logIvoryRaven(data);
    }
}
