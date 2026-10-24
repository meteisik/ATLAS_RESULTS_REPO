import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxOrbitSafe {

    public void handleOnyxOrbit() {
        String data;
        data = System.getenv("ONYX_ORBIT_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxOrbitSafeSink()).logOnyxOrbit(dataArray);
    }
}

class CWE117_P08_V1_OnyxOrbitSafeSink {
    public void logOnyxOrbit(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxOrbitLogger = Logger.getLogger("onyxOrbit.audit");
        onyxOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
