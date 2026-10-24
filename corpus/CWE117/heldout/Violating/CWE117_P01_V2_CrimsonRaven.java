import java.util.logging.Logger;

public class CWE117_P01_V2_CrimsonRaven {
    private static int privateFive = 5;

    public void handleCrimsonRaven() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("CRIMSON_RAVEN_USER");
        } else {
            data = null;
        }
        Logger crimsonRavenLogger = Logger.getLogger("crimsonRaven.audit");
        crimsonRavenLogger.info("Login attempt for user " + data);
    }
}
