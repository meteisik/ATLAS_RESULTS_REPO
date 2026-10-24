import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenSundial {

    private String readGoldenSundial() {
        String data;
        data = System.getenv("GOLDEN_SUNDIAL_USER");
        return data;
    }

    public void handleGoldenSundial() {
        String data = readGoldenSundial();
        Logger goldenSundialLogger = Logger.getLogger("goldenSundial.audit");
        goldenSundialLogger.info("Login attempt for user " + data);
    }
}
