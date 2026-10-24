import java.util.logging.Logger;

public class CWE117_P01_V2_JadeMantisSafe {

    public void handleJadeMantis() {
        String data;
        if (5 == 5) {
            data = System.getenv("JADE_MANTIS_USER");
        } else {
            data = null;
        }
        Logger jadeMantisLogger = Logger.getLogger("jadeMantis.audit");
        jadeMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
