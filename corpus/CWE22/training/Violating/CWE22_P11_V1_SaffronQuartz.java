import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;

public class CWE22_P11_V1_SaffronQuartz {

    public void openSaffronQuartz() throws IOException {
        String data;
        data = System.getenv("SAFFRON_QUARTZ_PATH");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SaffronQuartzSink()).readSaffronQuartz(dataHashMap);
    }
}

class CWE22_P11_V1_SaffronQuartzSink {
    public void readSaffronQuartz(HashMap<Integer, String> dataHashMap) throws IOException {
        String data = dataHashMap.get(2);
        String saffronQuartzRoot = "/home/user/uploads/";
        File saffronQuartzFile = new File(saffronQuartzRoot + data);
        FileInputStream saffronQuartzStream = new FileInputStream(saffronQuartzFile);
        saffronQuartzStream.close();
    }
}
