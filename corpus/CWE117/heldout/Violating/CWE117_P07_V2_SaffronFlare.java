import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronFlare {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSaffronFlare() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = (new CWE117_P07_V2_SaffronFlareSource()).readSaffronFlare();
        } else {
            data = null;
        }
        Logger saffronFlareLogger = Logger.getLogger("saffronFlare.audit");
        saffronFlareLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SaffronFlareSource {
    public String readSaffronFlare() {
        String data;
        data = System.getenv("SAFFRON_FLARE_USER");
        return data;
    }
}
