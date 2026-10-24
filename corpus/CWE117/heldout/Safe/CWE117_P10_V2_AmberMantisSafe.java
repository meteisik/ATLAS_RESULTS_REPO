import java.util.logging.Logger;

public class CWE117_P10_V2_AmberMantisSafe {
    private static boolean privateTrue = true;

    public static String data;

    public void handleAmberMantis() {
        if (privateTrue) {
            data = System.getenv("AMBER_MANTIS_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberMantisSafeSink()).logAmberMantis();
    }
}

class CWE117_P10_V2_AmberMantisSafeSink {
    public void logAmberMantis() {
        String data = CWE117_P10_V2_AmberMantisSafe.data;
        Logger amberMantisLogger = Logger.getLogger("amberMantis.audit");
        amberMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
