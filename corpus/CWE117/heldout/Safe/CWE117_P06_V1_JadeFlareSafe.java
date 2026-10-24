import java.util.logging.Logger;

public class CWE117_P06_V1_JadeFlareSafe {

    public void handleJadeFlare() {
        String data;
        data = System.getenv("JADE_FLARE_USER");
        (new CWE117_P06_V1_JadeFlareSafeSink()).logJadeFlare(data);
    }
}

class CWE117_P06_V1_JadeFlareSafeSink {
    public void logJadeFlare(String data) {
        Logger jadeFlareLogger = Logger.getLogger("jadeFlare.audit");
        jadeFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
