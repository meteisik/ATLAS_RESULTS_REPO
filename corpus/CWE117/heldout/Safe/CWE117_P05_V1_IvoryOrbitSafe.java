import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryOrbitSafe {

    private String ivoryOrbitData;

    private void logIvoryOrbit() {
        String data = ivoryOrbitData;
        Logger ivoryOrbitLogger = Logger.getLogger("ivoryOrbit.audit");
        ivoryOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryOrbit() {
        String data;
        data = System.getenv("IVORY_ORBIT_USER");
        ivoryOrbitData = data;
        logIvoryOrbit();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
