import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonRaven {

    private void logCrimsonRaven(String data) {
        Logger crimsonRavenLogger = Logger.getLogger("crimsonRaven.audit");
        crimsonRavenLogger.info("Login attempt for user " + data);
    }

    public void handleCrimsonRaven() {
        String data;
        data = System.getenv("CRIMSON_RAVEN_USER");
        logCrimsonRaven(data);
    }
}
