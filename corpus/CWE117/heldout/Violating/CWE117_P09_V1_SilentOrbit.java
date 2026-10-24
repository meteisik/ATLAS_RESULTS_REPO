import java.util.logging.Logger;

public class CWE117_P09_V1_SilentOrbit {

    static class Container {
        public String containerOne;
    }

    public void handleSilentOrbit() {
        String data;
        data = System.getenv("SILENT_ORBIT_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentOrbitSink()).logSilentOrbit(dataContainer);
    }
}

class CWE117_P09_V1_SilentOrbitSink {
    public void logSilentOrbit(CWE117_P09_V1_SilentOrbit.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentOrbitLogger = Logger.getLogger("silentOrbit.audit");
        silentOrbitLogger.info("Login attempt for user " + data);
    }
}
