import java.util.logging.Logger;

public class CWE117_P01_V2_CrimsonOrbitSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleCrimsonOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_ORBIT_USER");
        } else {
            data = null;
        }
        Logger crimsonOrbitLogger = Logger.getLogger("crimsonOrbit.audit");
        crimsonOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
