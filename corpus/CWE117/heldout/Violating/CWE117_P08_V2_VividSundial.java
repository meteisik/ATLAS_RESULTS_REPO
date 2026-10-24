import java.util.logging.Logger;

public class CWE117_P08_V2_VividSundial {

    public void handleVividSundial() {
        String data;
        while (true) {
            data = System.getenv("VIVID_SUNDIAL_USER");
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VividSundialSink()).logVividSundial(dataArray);
    }
}

class CWE117_P08_V2_VividSundialSink {
    public void logVividSundial(String[] dataArray) {
        String data = dataArray[2];
        Logger vividSundialLogger = Logger.getLogger("vividSundial.audit");
        vividSundialLogger.info("Login attempt for user " + data);
    }
}
