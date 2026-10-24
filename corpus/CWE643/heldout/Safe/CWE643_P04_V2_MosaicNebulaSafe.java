import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V2_MosaicNebulaSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String sourceMosaicNebula() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void runMosaicNebula() throws XPathExpressionException {
        String data = sourceMosaicNebula();
        String mosaicNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            mosaicNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            mosaicNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] mosaicNebulaTokens = data.split("||");
            if (mosaicNebulaTokens.length < 2) {
                return;
            }
            String mosaicNebulaUser = mosaicNebulaTokens[0];
            String mosaicNebulaPass = mosaicNebulaTokens[1];
            XPath mosaicNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource mosaicNebulaXml = new InputSource(mosaicNebulaXmlFile);
            String mosaicNebulaQuery = "//users/user[name/text()='" + mosaicNebulaUser
                    + "' and pass/text()='" + mosaicNebulaPass + "']" + "/secret/text()";
            String mosaicNebulaSecret = (String) mosaicNebulaXPath.evaluate(mosaicNebulaQuery, mosaicNebulaXml, XPathConstants.STRING);
            System.out.println(mosaicNebulaSecret);
        }
    }
}
