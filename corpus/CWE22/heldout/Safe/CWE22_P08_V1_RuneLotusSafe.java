import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_RuneLotusSafe {

    public void openRuneLotus() {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_RuneLotusSafeSink()).readRuneLotus(dataArray);
    }
}

class CWE22_P08_V1_RuneLotusSafeSink {
    public void readRuneLotus(String[] dataArray) {
        String data = dataArray[2];
        String runeLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File runeLotusFile = new File(runeLotusRoot + data);
            FileInputStream runeLotusStream = null;
            InputStreamReader runeLotusStreamReader = null;
            BufferedReader runeLotusReader = null;
            if (runeLotusFile.exists() && runeLotusFile.isFile()) {
                try {
                    runeLotusStream = new FileInputStream(runeLotusFile);
                    runeLotusStreamReader = new InputStreamReader(runeLotusStream, "UTF-8");
                    runeLotusReader = new BufferedReader(runeLotusStreamReader);
                    System.out.println(runeLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_RuneLotusSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeLotusReader != null) {
                            runeLotusReader.close();
                        }
                        if (runeLotusStreamReader != null) {
                            runeLotusStreamReader.close();
                        }
                        if (runeLotusStream != null) {
                            runeLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_RuneLotusSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
