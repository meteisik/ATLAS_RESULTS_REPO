import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxOrbitSafe {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxOrbit() {
        String data;
        data = System.getenv("ONYX_ORBIT_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxOrbitSafeSink()).logOnyxOrbit(dataContainer);
    }
}

class CWE117_P09_V1_OnyxOrbitSafeSink {
    public void logOnyxOrbit(CWE117_P09_V1_OnyxOrbitSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxOrbitLogger = Logger.getLogger("onyxOrbit.audit");
        onyxOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
