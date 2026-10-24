import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_MosaicRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void sinkMosaicRaven(String data) throws XPathExpressionException {
        String mosaicRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            mosaicRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            mosaicRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] mosaicRavenTokens = data.split("||");
            if (mosaicRavenTokens.length < 2) {
                return;
            }
            String mosaicRavenUser = mosaicRavenTokens[0];
            String mosaicRavenPass = mosaicRavenTokens[1];
            XPath mosaicRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource mosaicRavenXml = new InputSource(mosaicRavenXmlFile);
            String mosaicRavenQuery = "//users/user[name/text()='" + mosaicRavenUser
                    + "' and pass/text()='" + mosaicRavenPass + "']" + "/secret/text()";
            String mosaicRavenSecret = (String) mosaicRavenXPath.evaluate(mosaicRavenQuery, mosaicRavenXml, XPathConstants.STRING);
            System.out.println(mosaicRavenSecret);
        }
    }

    public void runMosaicRaven() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("MOSAIC_RAVEN_ADD");
        } else {
            data = null;
        }
        sinkMosaicRaven(data);
    }
}
