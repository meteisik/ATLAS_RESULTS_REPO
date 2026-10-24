import java.util.logging.Logger;

public class CWE117_P02_V2_LunarHelix {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleLunarHelix() {
        String dataCopy;
        {
            String data;
            if (IO.staticReturnsTrue()) {
                data = System.getenv("LUNAR_HELIX_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger lunarHelixLogger = Logger.getLogger("lunarHelix.audit");
            lunarHelixLogger.info("Login attempt for user " + data);
        }
    }
}
