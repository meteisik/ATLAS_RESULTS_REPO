import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronFlareSafe {

    public static String data;

    public void handleSaffronFlare() {
        data = System.getenv("SAFFRON_FLARE_USER");
        (new CWE117_P10_V1_SaffronFlareSafeSink()).logSaffronFlare();
    }
}

class CWE117_P10_V1_SaffronFlareSafeSink {
    public void logSaffronFlare() {
        String data = CWE117_P10_V1_SaffronFlareSafe.data;
        Logger saffronFlareLogger = Logger.getLogger("saffronFlare.audit");
        saffronFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
