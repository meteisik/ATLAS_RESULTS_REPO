import java.util.logging.Logger;

public class CWE117_P04_V1_CrimsonRaven {

    private String readCrimsonRaven() {
        String data;
        data = System.getenv("CRIMSON_RAVEN_USER");
        return data;
    }

    public void handleCrimsonRaven() {
        String data = readCrimsonRaven();
        Logger crimsonRavenLogger = Logger.getLogger("crimsonRaven.audit");
        crimsonRavenLogger.info("Login attempt for user " + data);
    }
}
