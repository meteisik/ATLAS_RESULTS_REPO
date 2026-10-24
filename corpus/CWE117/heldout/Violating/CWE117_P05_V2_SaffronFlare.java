import java.util.logging.Logger;

public class CWE117_P05_V2_SaffronFlare {
    private static boolean privateReturnsTrue() { return true; }

    private String saffronFlareData;

    private void logSaffronFlare() {
        String data = saffronFlareData;
        Logger saffronFlareLogger = Logger.getLogger("saffronFlare.audit");
        saffronFlareLogger.info("Login attempt for user " + data);
    }

    public void handleSaffronFlare() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SAFFRON_FLARE_USER");
        } else {
            data = null;
        }
        saffronFlareData = data;
        logSaffronFlare();
    }
}
