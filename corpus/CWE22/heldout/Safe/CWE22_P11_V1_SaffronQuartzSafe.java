import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_SaffronQuartzSafe {

    public void openSaffronQuartz() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SaffronQuartzSafeSink()).readSaffronQuartz(dataHashMap);
    }
}

class CWE22_P11_V1_SaffronQuartzSafeSink {
    public void readSaffronQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String saffronQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronQuartzFile = new File(saffronQuartzRoot + data);
            FileInputStream saffronQuartzStream = null;
            InputStreamReader saffronQuartzStreamReader = null;
            BufferedReader saffronQuartzReader = null;
            if (saffronQuartzFile.exists() && saffronQuartzFile.isFile()) {
                try {
                    saffronQuartzStream = new FileInputStream(saffronQuartzFile);
                    saffronQuartzStreamReader = new InputStreamReader(saffronQuartzStream, "UTF-8");
                    saffronQuartzReader = new BufferedReader(saffronQuartzStreamReader);
                    System.out.println(saffronQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_SaffronQuartzSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronQuartzReader != null) {
                            saffronQuartzReader.close();
                        }
                        if (saffronQuartzStreamReader != null) {
                            saffronQuartzStreamReader.close();
                        }
                        if (saffronQuartzStream != null) {
                            saffronQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_SaffronQuartzSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
