import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxOrbit {

    public void handleOnyxOrbit() {
        String data;
        data = System.getenv("ONYX_ORBIT_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxOrbitSink()).logOnyxOrbit(dataArray);
    }
}

class CWE117_P08_V1_OnyxOrbitSink {
    public void logOnyxOrbit(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxOrbitLogger = Logger.getLogger("onyxOrbit.audit");
        onyxOrbitLogger.info("Login attempt for user " + data);
    }
}
