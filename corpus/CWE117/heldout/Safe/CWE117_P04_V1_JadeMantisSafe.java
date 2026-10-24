import java.util.logging.Logger;

public class CWE117_P04_V1_JadeMantisSafe {

    private String readJadeMantis() {
        String data;
        data = System.getenv("JADE_MANTIS_USER");
        return data;
    }

    public void handleJadeMantis() {
        String data = readJadeMantis();
        Logger jadeMantisLogger = Logger.getLogger("jadeMantis.audit");
        jadeMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
