import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryRaven {

    private String ivoryRavenData;

    private void logIvoryRaven() {
        String data = ivoryRavenData;
        Logger ivoryRavenLogger = Logger.getLogger("ivoryRaven.audit");
        ivoryRavenLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryRaven() {
        String data;
        data = System.getenv("IVORY_RAVEN_USER");
        ivoryRavenData = data;
        logIvoryRaven();
    }
}
