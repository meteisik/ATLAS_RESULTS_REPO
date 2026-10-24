import java.util.logging.Logger;

public class CWE117_P03_V2_JadeMantisSafe {
    private static int privateFive = 5;

    private void logJadeMantis(String data) {
        Logger jadeMantisLogger = Logger.getLogger("jadeMantis.audit");
        jadeMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeMantis() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("JADE_MANTIS_USER");
        } else {
            data = null;
        }
        logJadeMantis(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
