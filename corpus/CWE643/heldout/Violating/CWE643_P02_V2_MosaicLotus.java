import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_MosaicLotus {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runMosaicLotus() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_TRUE) {
                data = System.getenv("MOSAIC_LOTUS_ADD");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String mosaicLotusXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                mosaicLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                mosaicLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] mosaicLotusTokens = data.split("||");
                if (mosaicLotusTokens.length < 2) {
                    return;
                }
                String mosaicLotusUser = mosaicLotusTokens[0];
                String mosaicLotusPass = mosaicLotusTokens[1];
                XPath mosaicLotusXPath = XPathFactory.newInstance().newXPath();
                InputSource mosaicLotusXml = new InputSource(mosaicLotusXmlFile);
                String mosaicLotusQuery = "//users/user[name/text()='" + mosaicLotusUser
                        + "' and pass/text()='" + mosaicLotusPass + "']" + "/secret/text()";
                String mosaicLotusSecret = (String) mosaicLotusXPath.evaluate(mosaicLotusQuery, mosaicLotusXml, XPathConstants.STRING);
                System.out.println(mosaicLotusSecret);
            }
        }
    }
}
