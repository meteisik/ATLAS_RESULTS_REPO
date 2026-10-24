import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronFlare {

    public static String data;

    public void handleSaffronFlare() {
        data = System.getenv("SAFFRON_FLARE_USER");
        (new CWE117_P10_V1_SaffronFlareSink()).logSaffronFlare();
    }
}

class CWE117_P10_V1_SaffronFlareSink {
    public void logSaffronFlare() {
        String data = CWE117_P10_V1_SaffronFlare.data;
        Logger saffronFlareLogger = Logger.getLogger("saffronFlare.audit");
        saffronFlareLogger.info("Login attempt for user " + data);
    }
}
