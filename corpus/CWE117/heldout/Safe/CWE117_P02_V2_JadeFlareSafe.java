import java.util.logging.Logger;

public class CWE117_P02_V2_JadeFlareSafe {

    public void handleJadeFlare() {
        String dataCopy;
        {
            String data;
            if (5 == 5) {
                data = System.getenv("JADE_FLARE_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger jadeFlareLogger = Logger.getLogger("jadeFlare.audit");
            jadeFlareLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
