import java.util.logging.Logger;

public class CWE117_P03_V1_CobaltOrbitSafe {

    private void logCobaltOrbit(String data) {
        Logger cobaltOrbitLogger = Logger.getLogger("cobaltOrbit.audit");
        cobaltOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCobaltOrbit() {
        String data;
        data = System.getenv("COBALT_ORBIT_USER");
        logCobaltOrbit(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
