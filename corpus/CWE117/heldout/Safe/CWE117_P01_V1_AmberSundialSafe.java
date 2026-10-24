import java.util.logging.Logger;

public class CWE117_P01_V1_AmberSundialSafe {

    public void handleAmberSundial() {
        String data;
        data = System.getenv("AMBER_SUNDIAL_USER");
        Logger amberSundialLogger = Logger.getLogger("amberSundial.audit");
        amberSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
