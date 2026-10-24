import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronCascadeSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSaffronCascade() {
        String data;
        if (IO.staticTrue) {
            data = (new CWE117_P07_V2_SaffronCascadeSafeSource()).readSaffronCascade();
        } else {
            data = null;
        }
        Logger saffronCascadeLogger = Logger.getLogger("saffronCascade.audit");
        saffronCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SaffronCascadeSafeSource {
    public String readSaffronCascade() {
        String data;
        data = System.getenv("SAFFRON_CASCADE_USER");
        return data;
    }
}
