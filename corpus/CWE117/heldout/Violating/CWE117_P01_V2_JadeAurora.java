import java.util.logging.Logger;

public class CWE117_P01_V2_JadeAurora {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleJadeAurora() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("JADE_AURORA_USER");
        } else {
            data = null;
        }
        Logger jadeAuroraLogger = Logger.getLogger("jadeAurora.audit");
        jadeAuroraLogger.info("Login attempt for user " + data);
    }
}
