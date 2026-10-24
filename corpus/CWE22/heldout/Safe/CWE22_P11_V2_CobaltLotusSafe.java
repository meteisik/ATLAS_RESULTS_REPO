import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_CobaltLotusSafe {

    public void openCobaltLotus() {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_CobaltLotusSafeSink()).readCobaltLotus(dataHashMap);
    }
}

class CWE22_P11_V2_CobaltLotusSafeSink {
    public void readCobaltLotus(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String cobaltLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File cobaltLotusFile = new File(cobaltLotusRoot + data);
            FileInputStream cobaltLotusStream = null;
            InputStreamReader cobaltLotusStreamReader = null;
            BufferedReader cobaltLotusReader = null;
            if (cobaltLotusFile.exists() && cobaltLotusFile.isFile()) {
                try {
                    cobaltLotusStream = new FileInputStream(cobaltLotusFile);
                    cobaltLotusStreamReader = new InputStreamReader(cobaltLotusStream, "UTF-8");
                    cobaltLotusReader = new BufferedReader(cobaltLotusStreamReader);
                    System.out.println(cobaltLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_CobaltLotusSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (cobaltLotusReader != null) {
                            cobaltLotusReader.close();
                        }
                        if (cobaltLotusStreamReader != null) {
                            cobaltLotusStreamReader.close();
                        }
                        if (cobaltLotusStream != null) {
                            cobaltLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_CobaltLotusSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
