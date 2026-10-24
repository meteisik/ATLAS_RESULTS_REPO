import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_ObsidianKestrelSafe {

    public void openObsidianKestrel() {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_ObsidianKestrelSafeSink()).readObsidianKestrel(dataArray);
    }
}

class CWE22_P08_V1_ObsidianKestrelSafeSink {
    public void readObsidianKestrel(String[] dataArray) {
        String data = dataArray[2];
        String obsidianKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianKestrelFile = new File(obsidianKestrelRoot + data);
            FileInputStream obsidianKestrelStream = null;
            InputStreamReader obsidianKestrelStreamReader = null;
            BufferedReader obsidianKestrelReader = null;
            if (obsidianKestrelFile.exists() && obsidianKestrelFile.isFile()) {
                try {
                    obsidianKestrelStream = new FileInputStream(obsidianKestrelFile);
                    obsidianKestrelStreamReader = new InputStreamReader(obsidianKestrelStream, "UTF-8");
                    obsidianKestrelReader = new BufferedReader(obsidianKestrelStreamReader);
                    System.out.println(obsidianKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_ObsidianKestrelSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianKestrelReader != null) {
                            obsidianKestrelReader.close();
                        }
                        if (obsidianKestrelStreamReader != null) {
                            obsidianKestrelStreamReader.close();
                        }
                        if (obsidianKestrelStream != null) {
                            obsidianKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_ObsidianKestrelSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
