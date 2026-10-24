import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_OnyxLotus {

    public void openOnyxLotus() {
        String data;
        data = System.getenv("ONYX_LOTUS_PATH");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_OnyxLotusSink()).readOnyxLotus(dataArray);
    }
}

class CWE22_P08_V1_OnyxLotusSink {
    public void readOnyxLotus(String[] dataArray) {
        String data = dataArray[2];
        String onyxLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxLotusFile = new File(onyxLotusRoot + data);
            FileInputStream onyxLotusStream = null;
            InputStreamReader onyxLotusStreamReader = null;
            BufferedReader onyxLotusReader = null;
            if (onyxLotusFile.exists() && onyxLotusFile.isFile()) {
                try {
                    onyxLotusStream = new FileInputStream(onyxLotusFile);
                    onyxLotusStreamReader = new InputStreamReader(onyxLotusStream, "UTF-8");
                    onyxLotusReader = new BufferedReader(onyxLotusStreamReader);
                    System.out.println(onyxLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_OnyxLotusSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxLotusReader != null) {
                            onyxLotusReader.close();
                        }
                        if (onyxLotusStreamReader != null) {
                            onyxLotusStreamReader.close();
                        }
                        if (onyxLotusStream != null) {
                            onyxLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_OnyxLotusSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
