import java.util.logging.Logger;

public class CWE117_P02_V2_IvoryNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleIvoryNebula() {
        String dataCopy;
        {
            String data;
            if (IO.STATIC_FINAL_FIVE == 5) {
                data = System.getenv("IVORY_NEBULA_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger ivoryNebulaLogger = Logger.getLogger("ivoryNebula.audit");
            ivoryNebulaLogger.info("Login attempt for user " + data);
        }
    }
}
