import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleOnyxNebula() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("ONYX_NEBULA_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxNebulaSink()).logOnyxNebula(data);
    }
}

class CWE117_P06_V2_OnyxNebulaSink {
    public void logOnyxNebula(String data) {
        Logger onyxNebulaLogger = Logger.getLogger("onyxNebula.audit");
        onyxNebulaLogger.info("Login attempt for user " + data);
    }
}
