import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxOrbit {

    public void handleOnyxOrbit() {
        String data;
        data = (new CWE117_P07_V1_OnyxOrbitSource()).readOnyxOrbit();
        Logger onyxOrbitLogger = Logger.getLogger("onyxOrbit.audit");
        onyxOrbitLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_OnyxOrbitSource {
    public String readOnyxOrbit() {
        String data;
        data = System.getenv("ONYX_ORBIT_USER");
        return data;
    }
}
