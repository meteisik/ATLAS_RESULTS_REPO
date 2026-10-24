import java.util.logging.Logger;

public class CWE117_P10_V2_AmberSundial {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void handleAmberSundial() {
        if (privateReturnsTrue()) {
            data = System.getenv("AMBER_SUNDIAL_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberSundialSink()).logAmberSundial();
    }
}

class CWE117_P10_V2_AmberSundialSink {
    public void logAmberSundial() {
        String data = CWE117_P10_V2_AmberSundial.data;
        Logger amberSundialLogger = Logger.getLogger("amberSundial.audit");
        amberSundialLogger.info("Login attempt for user " + data);
    }
}
