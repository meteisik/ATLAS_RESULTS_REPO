import java.util.logging.Logger;

public class CWE117_P01_V2_CrimsonOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleCrimsonOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_ORBIT_USER");
        } else {
            data = null;
        }
        Logger crimsonOrbitLogger = Logger.getLogger("crimsonOrbit.audit");
        crimsonOrbitLogger.info("Login attempt for user " + data);
    }
}
