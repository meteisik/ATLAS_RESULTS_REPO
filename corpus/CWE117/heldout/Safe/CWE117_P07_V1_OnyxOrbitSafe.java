import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxOrbitSafe {

    public void handleOnyxOrbit() {
        String data;
        data = (new CWE117_P07_V1_OnyxOrbitSafeSource()).readOnyxOrbit();
        Logger onyxOrbitLogger = Logger.getLogger("onyxOrbit.audit");
        onyxOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_OnyxOrbitSafeSource {
    public String readOnyxOrbit() {
        String data;
        data = System.getenv("ONYX_ORBIT_USER");
        return data;
    }
}
