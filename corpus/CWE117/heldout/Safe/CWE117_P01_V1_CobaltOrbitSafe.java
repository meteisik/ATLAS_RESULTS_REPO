import java.util.logging.Logger;

public class CWE117_P01_V1_CobaltOrbitSafe {

    public void handleCobaltOrbit() {
        String data;
        data = System.getenv("COBALT_ORBIT_USER");
        Logger cobaltOrbitLogger = Logger.getLogger("cobaltOrbit.audit");
        cobaltOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
