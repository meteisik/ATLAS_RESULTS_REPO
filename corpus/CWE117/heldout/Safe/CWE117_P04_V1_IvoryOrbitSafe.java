import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryOrbitSafe {

    private String readIvoryOrbit() {
        String data;
        data = System.getenv("IVORY_ORBIT_USER");
        return data;
    }

    public void handleIvoryOrbit() {
        String data = readIvoryOrbit();
        Logger ivoryOrbitLogger = Logger.getLogger("ivoryOrbit.audit");
        ivoryOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
