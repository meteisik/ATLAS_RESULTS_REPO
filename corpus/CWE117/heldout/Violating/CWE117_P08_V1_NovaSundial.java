import java.util.logging.Logger;

public class CWE117_P08_V1_NovaSundial {

    public void handleNovaSundial() {
        String data;
        data = System.getenv("NOVA_SUNDIAL_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_NovaSundialSink()).logNovaSundial(dataArray);
    }
}

class CWE117_P08_V1_NovaSundialSink {
    public void logNovaSundial(String[] dataArray) {
        String data = dataArray[2];
        Logger novaSundialLogger = Logger.getLogger("novaSundial.audit");
        novaSundialLogger.info("Login attempt for user " + data);
    }
}
