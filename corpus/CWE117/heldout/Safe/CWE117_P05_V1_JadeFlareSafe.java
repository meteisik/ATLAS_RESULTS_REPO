import java.util.logging.Logger;

public class CWE117_P05_V1_JadeFlareSafe {

    private String jadeFlareData;

    private void logJadeFlare() {
        String data = jadeFlareData;
        Logger jadeFlareLogger = Logger.getLogger("jadeFlare.audit");
        jadeFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeFlare() {
        String data;
        data = System.getenv("JADE_FLARE_USER");
        jadeFlareData = data;
        logJadeFlare();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
