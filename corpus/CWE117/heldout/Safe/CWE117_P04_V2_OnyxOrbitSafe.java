import java.util.logging.Logger;

public class CWE117_P04_V2_OnyxOrbitSafe {
    private static int privateFive = 5;

    private String readOnyxOrbit() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ONYX_ORBIT_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleOnyxOrbit() {
        String data = readOnyxOrbit();
        Logger onyxOrbitLogger = Logger.getLogger("onyxOrbit.audit");
        onyxOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
