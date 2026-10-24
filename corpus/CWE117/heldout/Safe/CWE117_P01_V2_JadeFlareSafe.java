import java.util.logging.Logger;

public class CWE117_P01_V2_JadeFlareSafe {

    public void handleJadeFlare() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("JADE_FLARE_USER");
        }
        Logger jadeFlareLogger = Logger.getLogger("jadeFlare.audit");
        jadeFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
