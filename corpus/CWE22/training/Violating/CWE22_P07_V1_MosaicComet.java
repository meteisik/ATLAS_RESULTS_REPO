import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P07_V1_MosaicComet {

    public void openMosaicComet() throws IOException {
        String data;
        data = (new CWE22_P07_V1_MosaicCometSource()).locateMosaicComet();
        String mosaicCometRoot = "/home/user/uploads/";
        File mosaicCometFile = new File(mosaicCometRoot + data);
        FileInputStream mosaicCometStream = new FileInputStream(mosaicCometFile);
        mosaicCometStream.close();
    }
}

class CWE22_P07_V1_MosaicCometSource {
    public String locateMosaicComet() throws IOException {
        String data;
        data = System.getenv("MOSAIC_COMET_PATH");
        return data;
    }
}
