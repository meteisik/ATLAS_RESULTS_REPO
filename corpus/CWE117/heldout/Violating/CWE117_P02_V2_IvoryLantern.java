import java.util.logging.Logger;

public class CWE117_P02_V2_IvoryLantern {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleIvoryLantern() {
        String dataCopy;
        {
            String data;
            if (IO.staticTrue) {
                data = System.getenv("IVORY_LANTERN_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger ivoryLanternLogger = Logger.getLogger("ivoryLantern.audit");
            ivoryLanternLogger.info("Login attempt for user " + data);
        }
    }
}
