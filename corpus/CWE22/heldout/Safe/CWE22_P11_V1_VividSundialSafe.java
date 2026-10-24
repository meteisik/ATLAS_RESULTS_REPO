import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_VividSundialSafe {

    public void openVividSundial() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_VividSundialSafeSink()).readVividSundial(dataHashMap);
    }
}

class CWE22_P11_V1_VividSundialSafeSink {
    public void readVividSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String vividSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File vividSundialFile = new File(vividSundialRoot + data);
            FileInputStream vividSundialStream = null;
            InputStreamReader vividSundialStreamReader = null;
            BufferedReader vividSundialReader = null;
            if (vividSundialFile.exists() && vividSundialFile.isFile()) {
                try {
                    vividSundialStream = new FileInputStream(vividSundialFile);
                    vividSundialStreamReader = new InputStreamReader(vividSundialStream, "UTF-8");
                    vividSundialReader = new BufferedReader(vividSundialStreamReader);
                    System.out.println(vividSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_VividSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividSundialReader != null) {
                            vividSundialReader.close();
                        }
                        if (vividSundialStreamReader != null) {
                            vividSundialStreamReader.close();
                        }
                        if (vividSundialStream != null) {
                            vividSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_VividSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
