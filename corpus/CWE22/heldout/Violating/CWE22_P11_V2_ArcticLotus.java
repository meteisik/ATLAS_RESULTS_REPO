import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_ArcticLotus {

    public void openArcticLotus() {
        String data;
        if (true) {
            data = System.getenv("ARCTIC_LOTUS_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_ArcticLotusSink()).readArcticLotus(dataHashMap);
    }
}

class CWE22_P11_V2_ArcticLotusSink {
    public void readArcticLotus(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String arcticLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticLotusFile = new File(arcticLotusRoot + data);
            FileInputStream arcticLotusStream = null;
            InputStreamReader arcticLotusStreamReader = null;
            BufferedReader arcticLotusReader = null;
            if (arcticLotusFile.exists() && arcticLotusFile.isFile()) {
                try {
                    arcticLotusStream = new FileInputStream(arcticLotusFile);
                    arcticLotusStreamReader = new InputStreamReader(arcticLotusStream, "UTF-8");
                    arcticLotusReader = new BufferedReader(arcticLotusStreamReader);
                    System.out.println(arcticLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_ArcticLotusSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticLotusReader != null) {
                            arcticLotusReader.close();
                        }
                        if (arcticLotusStreamReader != null) {
                            arcticLotusStreamReader.close();
                        }
                        if (arcticLotusStream != null) {
                            arcticLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_ArcticLotusSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
