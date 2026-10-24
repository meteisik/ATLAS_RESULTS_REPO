import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_ObsidianKestrel {

    public void openObsidianKestrel() {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_PATH");
        (new CWE22_P06_V1_ObsidianKestrelSink()).readObsidianKestrel(data);
    }
}

class CWE22_P06_V1_ObsidianKestrelSink {
    public void readObsidianKestrel(String data) {
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
                    Logger.getLogger("CWE22_P06_V1_ObsidianKestrelSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P06_V1_ObsidianKestrelSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
