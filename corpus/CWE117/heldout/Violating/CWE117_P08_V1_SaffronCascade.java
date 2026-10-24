import java.util.logging.Logger;

public class CWE117_P08_V1_SaffronCascade {

    public void handleSaffronCascade() {
        String data;
        data = System.getenv("SAFFRON_CASCADE_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_SaffronCascadeSink()).logSaffronCascade(dataArray);
    }
}

class CWE117_P08_V1_SaffronCascadeSink {
    public void logSaffronCascade(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronCascadeLogger = Logger.getLogger("saffronCascade.audit");
        saffronCascadeLogger.info("Login attempt for user " + data);
    }
}
