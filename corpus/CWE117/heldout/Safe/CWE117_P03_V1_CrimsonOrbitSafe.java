import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonOrbitSafe {

    private void logCrimsonOrbit(String data) {
        Logger crimsonOrbitLogger = Logger.getLogger("crimsonOrbit.audit");
        crimsonOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCrimsonOrbit() {
        String data;
        data = System.getenv("CRIMSON_ORBIT_USER");
        logCrimsonOrbit(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
