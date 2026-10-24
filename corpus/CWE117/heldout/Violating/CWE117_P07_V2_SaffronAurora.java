import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronAurora {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSaffronAurora() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = (new CWE117_P07_V2_SaffronAuroraSource()).readSaffronAurora();
        } else {
            data = null;
        }
        Logger saffronAuroraLogger = Logger.getLogger("saffronAurora.audit");
        saffronAuroraLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SaffronAuroraSource {
    public String readSaffronAurora() {
        String data;
        data = System.getenv("SAFFRON_AURORA_USER");
        return data;
    }
}
