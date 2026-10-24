import java.util.logging.Logger;

public class CWE117_P06_V1_JadeMantisSafe {

    public void handleJadeMantis() {
        String data;
        data = System.getenv("JADE_MANTIS_USER");
        (new CWE117_P06_V1_JadeMantisSafeSink()).logJadeMantis(data);
    }
}

class CWE117_P06_V1_JadeMantisSafeSink {
    public void logJadeMantis(String data) {
        Logger jadeMantisLogger = Logger.getLogger("jadeMantis.audit");
        jadeMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
