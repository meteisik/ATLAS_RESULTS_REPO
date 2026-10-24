import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V2_MosaicOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String sourceMosaicOrbit() {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void runMosaicOrbit() throws XPathExpressionException {
        String data = sourceMosaicOrbit();
        String mosaicOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            mosaicOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            mosaicOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] mosaicOrbitTokens = data.split("||");
            if (mosaicOrbitTokens.length < 2) {
                return;
            }
            String mosaicOrbitUser = mosaicOrbitTokens[0];
            String mosaicOrbitPass = mosaicOrbitTokens[1];
            XPath mosaicOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource mosaicOrbitXml = new InputSource(mosaicOrbitXmlFile);
            String mosaicOrbitQuery = "//users/user[name/text()='" + mosaicOrbitUser
                    + "' and pass/text()='" + mosaicOrbitPass + "']" + "/secret/text()";
            String mosaicOrbitSecret = (String) mosaicOrbitXPath.evaluate(mosaicOrbitQuery, mosaicOrbitXml, XPathConstants.STRING);
            System.out.println(mosaicOrbitSecret);
        }
    }
}
