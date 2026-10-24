import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetCipher {

    public void handleVelvetCipher() {
        String data;
        data = System.getenv("VELVET_CIPHER_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetCipherSink()).logVelvetCipher(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetCipherSink {
    public void logVelvetCipher(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetCipherLogger = Logger.getLogger("velvetCipher.audit");
        velvetCipherLogger.info("Login attempt for user " + data);
    }
}
