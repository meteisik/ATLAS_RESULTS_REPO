import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_MosaicBeaconSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runMosaicBeacon() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (IO.staticFive == 5) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String mosaicBeaconXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                mosaicBeaconXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                mosaicBeaconXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] mosaicBeaconTokens = data.split("||");
                if (mosaicBeaconTokens.length < 2) {
                    return;
                }
                String mosaicBeaconUser = mosaicBeaconTokens[0];
                String mosaicBeaconPass = mosaicBeaconTokens[1];
                XPath mosaicBeaconXPath = XPathFactory.newInstance().newXPath();
                InputSource mosaicBeaconXml = new InputSource(mosaicBeaconXmlFile);
                String mosaicBeaconQuery = "//users/user[name/text()='" + mosaicBeaconUser
                        + "' and pass/text()='" + mosaicBeaconPass + "']" + "/secret/text()";
                String mosaicBeaconSecret = (String) mosaicBeaconXPath.evaluate(mosaicBeaconQuery, mosaicBeaconXml, XPathConstants.STRING);
                System.out.println(mosaicBeaconSecret);
            }
        }
    }
}
