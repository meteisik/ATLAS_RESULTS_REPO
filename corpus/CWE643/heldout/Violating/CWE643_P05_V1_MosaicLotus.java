import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_MosaicLotus {

    private String mosaicLotusData;

    private void sinkMosaicLotus() throws XPathExpressionException {
        String data = mosaicLotusData;
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

    public void runMosaicLotus() throws XPathExpressionException {
        String data;
        data = System.getenv("MOSAIC_LOTUS_ADD");
        mosaicLotusData = data;
        sinkMosaicLotus();
    }
}
