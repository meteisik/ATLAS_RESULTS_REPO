import java.util.logging.Logger;

public class CWE117_P10_V2_AmberFlareSafe {

    public static String data;

    public void handleAmberFlare() {
        if (5 == 5) {
            data = System.getenv("AMBER_FLARE_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberFlareSafeSink()).logAmberFlare();
    }
}

class CWE117_P10_V2_AmberFlareSafeSink {
    public void logAmberFlare() {
        String data = CWE117_P10_V2_AmberFlareSafe.data;
        Logger amberFlareLogger = Logger.getLogger("amberFlare.audit");
        amberFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
