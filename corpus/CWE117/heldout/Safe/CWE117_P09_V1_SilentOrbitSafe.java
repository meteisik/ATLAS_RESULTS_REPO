import java.util.logging.Logger;

public class CWE117_P09_V1_SilentOrbitSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSilentOrbit() {
        String data;
        data = System.getenv("SILENT_ORBIT_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentOrbitSafeSink()).logSilentOrbit(dataContainer);
    }
}

class CWE117_P09_V1_SilentOrbitSafeSink {
    public void logSilentOrbit(CWE117_P09_V1_SilentOrbitSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentOrbitLogger = Logger.getLogger("silentOrbit.audit");
        silentOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
