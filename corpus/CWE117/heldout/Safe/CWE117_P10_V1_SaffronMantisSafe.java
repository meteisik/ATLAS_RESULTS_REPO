import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronMantisSafe {

    public static String data;

    public void handleSaffronMantis() {
        data = System.getenv("SAFFRON_MANTIS_USER");
        (new CWE117_P10_V1_SaffronMantisSafeSink()).logSaffronMantis();
    }
}

class CWE117_P10_V1_SaffronMantisSafeSink {
    public void logSaffronMantis() {
        String data = CWE117_P10_V1_SaffronMantisSafe.data;
        Logger saffronMantisLogger = Logger.getLogger("saffronMantis.audit");
        saffronMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
