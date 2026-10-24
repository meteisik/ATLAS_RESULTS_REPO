import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_ObsidianHelixSafe {

    public void openObsidianHelix() {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_ObsidianHelixSafeSink()).readObsidianHelix(dataArray);
    }
}

class CWE22_P08_V1_ObsidianHelixSafeSink {
    public void readObsidianHelix(String[] dataArray) {
        String data = dataArray[2];
        String obsidianHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianHelixFile = new File(obsidianHelixRoot + data);
            FileInputStream obsidianHelixStream = null;
            InputStreamReader obsidianHelixStreamReader = null;
            BufferedReader obsidianHelixReader = null;
            if (obsidianHelixFile.exists() && obsidianHelixFile.isFile()) {
                try {
                    obsidianHelixStream = new FileInputStream(obsidianHelixFile);
                    obsidianHelixStreamReader = new InputStreamReader(obsidianHelixStream, "UTF-8");
                    obsidianHelixReader = new BufferedReader(obsidianHelixStreamReader);
                    System.out.println(obsidianHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_ObsidianHelixSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianHelixReader != null) {
                            obsidianHelixReader.close();
                        }
                        if (obsidianHelixStreamReader != null) {
                            obsidianHelixStreamReader.close();
                        }
                        if (obsidianHelixStream != null) {
                            obsidianHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_ObsidianHelixSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
