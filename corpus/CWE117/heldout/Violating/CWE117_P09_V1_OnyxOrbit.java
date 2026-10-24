import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxOrbit {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxOrbit() {
        String data;
        data = System.getenv("ONYX_ORBIT_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxOrbitSink()).logOnyxOrbit(dataContainer);
    }
}

class CWE117_P09_V1_OnyxOrbitSink {
    public void logOnyxOrbit(CWE117_P09_V1_OnyxOrbit.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxOrbitLogger = Logger.getLogger("onyxOrbit.audit");
        onyxOrbitLogger.info("Login attempt for user " + data);
    }
}
