import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxNebula {

    public void handleOnyxNebula() {
        String data;
        data = System.getenv("ONYX_NEBULA_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxNebulaSink()).logOnyxNebula(dataArray);
    }
}

class CWE117_P08_V1_OnyxNebulaSink {
    public void logOnyxNebula(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxNebulaLogger = Logger.getLogger("onyxNebula.audit");
        onyxNebulaLogger.info("Login attempt for user " + data);
    }
}
