import java.util.logging.Logger;

public class CWE117_P10_V2_VividSundial {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public void handleVividSundial() {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("VIVID_SUNDIAL_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_VividSundialSink()).logVividSundial();
    }
}

class CWE117_P10_V2_VividSundialSink {
    public void logVividSundial() {
        String data = CWE117_P10_V2_VividSundial.data;
        Logger vividSundialLogger = Logger.getLogger("vividSundial.audit");
        vividSundialLogger.info("Login attempt for user " + data);
    }
}
