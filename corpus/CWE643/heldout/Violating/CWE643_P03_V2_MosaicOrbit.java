import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_MosaicOrbit {
    private static boolean privateReturnsTrue() { return true; }

    private void sinkMosaicOrbit(String data) throws XPathExpressionException {
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

    public void runMosaicOrbit() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("MOSAIC_ORBIT_ADD");
        } else {
            data = null;
        }
        sinkMosaicOrbit(data);
    }
}
