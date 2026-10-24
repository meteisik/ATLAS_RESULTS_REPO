import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_IvoryHelix {
    private static boolean privateReturnsTrue() { return true; }

    public void openIvoryHelix() {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = System.getenv("IVORY_HELIX_PATH");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String ivoryHelixRoot = "/home/user/uploads/";
            if (data != null) {
                File ivoryHelixFile = new File(ivoryHelixRoot + data);
                FileInputStream ivoryHelixStream = null;
                InputStreamReader ivoryHelixStreamReader = null;
                BufferedReader ivoryHelixReader = null;
                if (ivoryHelixFile.exists() && ivoryHelixFile.isFile()) {
                    try {
                        ivoryHelixStream = new FileInputStream(ivoryHelixFile);
                        ivoryHelixStreamReader = new InputStreamReader(ivoryHelixStream, "UTF-8");
                        ivoryHelixReader = new BufferedReader(ivoryHelixStreamReader);
                        System.out.println(ivoryHelixReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V2_IvoryHelix").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (ivoryHelixReader != null) {
                                ivoryHelixReader.close();
                            }
                            if (ivoryHelixStreamReader != null) {
                                ivoryHelixStreamReader.close();
                            }
                            if (ivoryHelixStream != null) {
                                ivoryHelixStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V2_IvoryHelix").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
