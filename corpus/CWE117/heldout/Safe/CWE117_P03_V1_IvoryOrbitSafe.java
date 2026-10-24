import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryOrbitSafe {

    private void logIvoryOrbit(String data) {
        Logger ivoryOrbitLogger = Logger.getLogger("ivoryOrbit.audit");
        ivoryOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryOrbit() {
        String data;
        data = System.getenv("IVORY_ORBIT_USER");
        logIvoryOrbit(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
