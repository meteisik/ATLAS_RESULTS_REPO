import java.util.logging.Logger;

public class CWE117_P01_V2_GoldenSundial {

    public void handleGoldenSundial() {
        String data;
        if (true) {
            data = System.getenv("GOLDEN_SUNDIAL_USER");
        } else {
            data = null;
        }
        Logger goldenSundialLogger = Logger.getLogger("goldenSundial.audit");
        goldenSundialLogger.info("Login attempt for user " + data);
    }
}
