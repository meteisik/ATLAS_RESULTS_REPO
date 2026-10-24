import java.util.logging.Logger;

public class CWE117_P05_V1_JadeMantisSafe {

    private String jadeMantisData;

    private void logJadeMantis() {
        String data = jadeMantisData;
        Logger jadeMantisLogger = Logger.getLogger("jadeMantis.audit");
        jadeMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeMantis() {
        String data;
        data = System.getenv("JADE_MANTIS_USER");
        jadeMantisData = data;
        logJadeMantis();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
