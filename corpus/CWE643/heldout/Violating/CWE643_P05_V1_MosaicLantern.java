import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_MosaicLantern {

    private String mosaicLanternData;

    private void sinkMosaicLantern() throws XPathExpressionException {
        String data = mosaicLanternData;
        String mosaicLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            mosaicLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            mosaicLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] mosaicLanternTokens = data.split("||");
            if (mosaicLanternTokens.length < 2) {
                return;
            }
            String mosaicLanternUser = mosaicLanternTokens[0];
            String mosaicLanternPass = mosaicLanternTokens[1];
            XPath mosaicLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource mosaicLanternXml = new InputSource(mosaicLanternXmlFile);
            String mosaicLanternQuery = "//users/user[name/text()='" + mosaicLanternUser
                    + "' and pass/text()='" + mosaicLanternPass + "']" + "/secret/text()";
            String mosaicLanternSecret = (String) mosaicLanternXPath.evaluate(mosaicLanternQuery, mosaicLanternXml, XPathConstants.STRING);
            System.out.println(mosaicLanternSecret);
        }
    }

    public void runMosaicLantern() throws XPathExpressionException {
        String data;
        data = System.getenv("MOSAIC_LANTERN_ADD");
        mosaicLanternData = data;
        sinkMosaicLantern();
    }
}
