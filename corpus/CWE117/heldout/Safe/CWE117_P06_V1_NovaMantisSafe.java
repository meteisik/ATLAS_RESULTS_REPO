import java.util.logging.Logger;

public class CWE117_P06_V1_NovaMantisSafe {

    public void handleNovaMantis() {
        String data;
        data = System.getenv("NOVA_MANTIS_USER");
        (new CWE117_P06_V1_NovaMantisSafeSink()).logNovaMantis(data);
    }
}

class CWE117_P06_V1_NovaMantisSafeSink {
    public void logNovaMantis(String data) {
        Logger novaMantisLogger = Logger.getLogger("novaMantis.audit");
        novaMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
