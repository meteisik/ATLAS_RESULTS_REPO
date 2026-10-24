import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_RuneCometSafe {

    public void openRuneComet() {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_RuneCometSafeSink()).readRuneComet(dataArray);
    }
}

class CWE22_P08_V1_RuneCometSafeSink {
    public void readRuneComet(String[] dataArray) {
        String data = dataArray[2];
        String runeCometRoot = "/home/user/uploads/";
        if (data != null) {
            File runeCometFile = new File(runeCometRoot + data);
            FileInputStream runeCometStream = null;
            InputStreamReader runeCometStreamReader = null;
            BufferedReader runeCometReader = null;
            if (runeCometFile.exists() && runeCometFile.isFile()) {
                try {
                    runeCometStream = new FileInputStream(runeCometFile);
                    runeCometStreamReader = new InputStreamReader(runeCometStream, "UTF-8");
                    runeCometReader = new BufferedReader(runeCometStreamReader);
                    System.out.println(runeCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_RuneCometSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeCometReader != null) {
                            runeCometReader.close();
                        }
                        if (runeCometStreamReader != null) {
                            runeCometStreamReader.close();
                        }
                        if (runeCometStream != null) {
                            runeCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_RuneCometSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
