import java.util.logging.Logger;

public class CWE117_P01_V2_IvoryLotus {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleIvoryLotus() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("IVORY_LOTUS_USER");
        } else {
            data = null;
        }
        Logger ivoryLotusLogger = Logger.getLogger("ivoryLotus.audit");
        ivoryLotusLogger.info("Login attempt for user " + data);
    }
}
